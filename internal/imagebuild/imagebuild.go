// Package imagebuild builds a container image from a source checkout with
// buildah.
//
// It is a port of the build step of the demo's buildah-rhtap task
// (tssc-validated-pattern), which carried this as a shell script inside the
// task YAML. The argument marshalling -- Dockerfile discovery, label and
// build-arg parsing, the push sequence -- is Go code with tests; buildah
// itself is exec'd from PATH.
package imagebuild

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/project-lightpath/cli-tools/internal/imageref"
	"github.com/project-lightpath/cli-tools/internal/tekton"
)

// Options mirrors the params of the task this replaces, so a thin wrapper
// can map them one to one onto flags.
type Options struct {
	// Image is the reference buildah produces, tag included.
	Image string

	// Dockerfile is the path to the build file, relative to the context.
	// The sample application keeps a Containerfile at its root, so callers
	// pass ./Containerfile.
	Dockerfile string

	// Context is the build context directory, relative to SourceDir.
	Context string

	TLSVerify bool

	// BuildArgs are "arg=value" strings for --build-arg.
	BuildArgs []string

	// BuildArgsFile is a file of build arguments, relative to SourceDir.
	// See https://www.mankier.com/1/buildah-build#--build-arg-file
	BuildArgsFile string

	// Labels is newline-separated "key=value" pairs stamped onto the
	// image. A string rather than a slice on purpose: the Tekton task
	// takes it as a string param so it cannot merge with the build-arg
	// array, and the two standard OCI source annotations belong here --
	// they reach the SBOM as syft:image:labels:* properties, which is
	// where RHTPA Exploit Intelligence finds the source repository and
	// commit it needs.
	Labels string

	// StorageDriver is the buildah storage driver (vfs in the cluster).
	StorageDriver string

	// SourceDir is the directory holding the checked-out source; the
	// Dockerfile is looked up inside it.
	SourceDir string

	// TaskRunName, when set, triggers an extra push of the same image to
	// a tag unique to this run, so concurrent runs cannot race on the
	// primary tag.
	TaskRunName string

	// OCIDir, when set, is where the image is additionally saved as an
	// OCI layout for the SBOM scan.
	OCIDir string

	// DigestFile is where buildah writes the push digest.
	DigestFile string
}

// Results carries what the pipeline needs to know about the built image.
// The field names are the Tekton result names of the task this replaces.
type Results struct {
	ImageDigest      string
	ImageURL         string
	BaseImagesDigest string
}

// FindDockerfile locates the build file the way the task's script did:
// inside the context directory first, then at the source root. The sample
// application's Containerfile sits at the root, so the second lookup is the
// one that fires there.
func FindDockerfile(sourceDir, context, dockerfile string) (string, error) {
	candidates := []string{
		filepath.Join(sourceDir, context, dockerfile),
		filepath.Join(sourceDir, dockerfile),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", fmt.Errorf("cannot find Dockerfile %s (looked in %s and %s)",
		dockerfile, candidates[0], candidates[1])
}

// ParseLabels splits newline-separated "key=value" labels, skipping blank
// lines. A line without "=" is passed through for buildah to reject: the
// values come from pipeline params, and silently dropping a malformed one
// would stamp the image without a label someone asked for.
func ParseLabels(labels string) []string {
	var out []string
	for _, line := range strings.Split(labels, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}

// UniqueTag is where the race-avoiding second push goes: the image reference
// with its tag replaced by the TaskRun's name.
func UniqueTag(image, taskRunName string) string {
	return imageref.StripTag(image) + ":" + taskRunName
}

// buildArgs assembles the argument vector for `buildah build`, in the order
// the task's script used.
func (o Options) buildArgs(dockerfilePath string) []string {
	args := []string{"build"}
	if o.BuildArgsFile != "" {
		args = append(args, "--build-arg-file="+filepath.Join(o.SourceDir, o.BuildArgsFile))
	}
	for _, label := range ParseLabels(o.Labels) {
		args = append(args, "--label="+label)
	}
	for _, a := range o.BuildArgs {
		args = append(args, "--build-arg="+a)
	}
	args = append(args,
		"--tls-verify="+strconv.FormatBool(o.TLSVerify),
		"--ulimit", "nofile=4096:4096",
		"-f", dockerfilePath,
		"-t", o.Image,
		filepath.Join(o.SourceDir, o.Context),
	)
	return args
}

// pushArgs assembles the argument vector for a `buildah push` of the image
// to the given docker:// target.
func (o Options) pushArgs(target string) []string {
	return []string{
		"push",
		"--tls-verify=" + strconv.FormatBool(o.TLSVerify),
		"--retry=5",
		"--digestfile=" + o.DigestFile,
		o.Image,
		"docker://" + target,
	}
}

// run executes a command. A variable so the sequencing tests can intercept
// every invocation without a container runtime.
var run = func(dir string, env []string, stdout, stderr io.Writer, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

// Build builds and pushes the image, returning the results the pipeline
// consumes.
//
// The sequence is the one the task's script performed: build, push to the
// primary reference, push to a run-unique tag when the TaskRun name is
// known, list the store for base-image digests, and save the image as an
// OCI layout when asked. The custom CA bundle the pipeline may mount is
// installed first, when there is one.
func Build(o Options, stdout, stderr io.Writer) (*Results, error) {
	if o.Image == "" {
		return nil, fmt.Errorf("no image reference given")
	}
	if o.StorageDriver == "" {
		o.StorageDriver = "vfs"
	}
	if o.DigestFile == "" {
		o.DigestFile = filepath.Join(os.TempDir(), "tssc-image-digest")
	}
	env := append(os.Environ(), "STORAGE_DRIVER="+o.StorageDriver)

	if err := trustCABundle(env, stdout, stderr); err != nil {
		return nil, err
	}

	dockerfilePath, err := FindDockerfile(o.SourceDir, o.Context, o.Dockerfile)
	if err != nil {
		return nil, err
	}

	if err := run(o.SourceDir, env, stdout, stderr, "buildah", o.buildArgs(dockerfilePath)...); err != nil {
		return nil, fmt.Errorf("building %s: %w", o.Image, err)
	}
	if err := run("", env, stdout, stderr, "buildah", o.pushArgs(o.Image)...); err != nil {
		return nil, fmt.Errorf("pushing %s: %w", o.Image, err)
	}
	if o.TaskRunName != "" {
		unique := UniqueTag(o.Image, o.TaskRunName)
		if err := run("", env, stdout, stderr, "buildah", o.pushArgs(unique)...); err != nil {
			return nil, fmt.Errorf("pushing %s: %w", unique, err)
		}
	}

	// Base images: everything in the store except the image just built.
	// The filtering reproduces the script's `grep -v $IMAGE` exactly,
	// which keeps any line not containing the full tagged reference --
	// including the run-unique tag's copy of the same image, should the
	// store list it.
	var bases bytes.Buffer
	if err := run("", env, &bases, stderr, "buildah", "images", "--format", "{{ .Name }}:{{ .Tag }}@{{ .Digest }}"); err != nil {
		return nil, fmt.Errorf("listing images: %w", err)
	}
	var kept []string
	for _, line := range strings.Split(strings.TrimRight(bases.String(), "\n"), "\n") {
		if line != "" && !strings.Contains(line, o.Image) {
			kept = append(kept, line)
		}
	}

	if o.OCIDir != "" {
		if err := run("", env, stdout, stderr, "buildah", "push", o.Image, "oci:"+o.OCIDir); err != nil {
			return nil, fmt.Errorf("saving %s as an OCI layout: %w", o.Image, err)
		}
	}

	digest, err := os.ReadFile(o.DigestFile)
	if err != nil {
		return nil, fmt.Errorf("reading image digest: %w", err)
	}
	return &Results{
		ImageDigest:      strings.TrimSpace(string(digest)),
		ImageURL:         o.Image,
		BaseImagesDigest: strings.Join(kept, "\n"),
	}, nil
}

// trustCABundle installs the pipeline's custom CA bundle when one is
// mounted, the way the task's script did. Outside a TaskRun there is no
// bundle and this does nothing.
func trustCABundle(env []string, stdout, stderr io.Writer) error {
	if _, err := os.Stat(tekton.CABundlePath); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("checking for CA bundle: %w", err)
	}
	bundle, err := os.ReadFile(tekton.CABundlePath)
	if err != nil {
		return fmt.Errorf("reading CA bundle: %w", err)
	}
	const anchor = "/etc/pki/ca-trust/source/anchors/tssc-ca-bundle.crt"
	if err := os.WriteFile(anchor, bundle, 0o644); err != nil {
		return fmt.Errorf("installing CA bundle: %w", err)
	}
	if err := run("", env, stdout, stderr, "update-ca-trust"); err != nil {
		return fmt.Errorf("update-ca-trust: %w", err)
	}
	return nil
}
