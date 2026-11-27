package imagebuild

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// srcRepo writes a checkout with a Containerfile at the root, like the
// sample application, and returns its path.
func srcRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Containerfile"), []byte("FROM scratch\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestFindDockerfile(t *testing.T) {
	dir := t.TempDir()
	// The sample application layout: Containerfile at the source root.
	if err := os.WriteFile(filepath.Join(dir, "Containerfile"), []byte("FROM scratch\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// And a context-local Dockerfile one level down, like the first
	// candidate the script checked.
	nested := filepath.Join(dir, "web", "Dockerfile")
	if err := os.MkdirAll(filepath.Dir(nested), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nested, []byte("FROM scratch\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if got, err := FindDockerfile(dir, "web", "Dockerfile"); err != nil || got != nested {
		t.Errorf("context-local lookup = %q, %v; want %q", got, err, nested)
	}
	if got, err := FindDockerfile(dir, ".", "./Containerfile"); err != nil || got != filepath.Join(dir, "Containerfile") {
		t.Errorf("root lookup = %q, %v", got, err)
	}
	if _, err := FindDockerfile(dir, ".", "./nope"); err == nil {
		t.Error("expected an error for a missing Dockerfile")
	}
}

func TestParseLabels(t *testing.T) {
	got := ParseLabels("org.opencontainers.image.source=https://example.com/repo\n\norg.opencontainers.image.revision=abc123\n")
	want := []string{
		"org.opencontainers.image.source=https://example.com/repo",
		"org.opencontainers.image.revision=abc123",
	}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("ParseLabels = %q, want %q", got, want)
	}
	if got := ParseLabels(""); got != nil {
		t.Errorf("ParseLabels(\"\") = %q, want nil", got)
	}
	if got := ParseLabels("\n \n"); got != nil {
		t.Errorf("ParseLabels of blank lines = %q, want nil", got)
	}
	// A malformed line passes through; buildah is the one to reject it.
	if got := ParseLabels("no-equals-sign"); len(got) != 1 || got[0] != "no-equals-sign" {
		t.Errorf("ParseLabels passes malformed lines through, got %q", got)
	}
}

func TestUniqueTag(t *testing.T) {
	if got := UniqueTag("quay.io/org/app:1.0", "run-abc"); got != "quay.io/org/app:run-abc" {
		t.Errorf("UniqueTag = %q", got)
	}
	if got := UniqueTag("quay.io:5000/org/app:1.0", "run-abc"); got != "quay.io:5000/org/app:run-abc" {
		t.Errorf("UniqueTag with port = %q", got)
	}
}

func TestBuildArgs(t *testing.T) {
	o := Options{
		Image:         "quay.io/org/app:1.0",
		TLSVerify:     true,
		BuildArgs:     []string{"a=1", "b=2"},
		BuildArgsFile: "args.txt",
		Labels:        "k=v",
		SourceDir:     "/src",
		Context:       ".",
	}
	got := o.buildArgs("/src/Dockerfile")
	want := []string{
		"build",
		"--build-arg-file=/src/args.txt",
		"--label=k=v",
		"--build-arg=a=1",
		"--build-arg=b=2",
		"--tls-verify=true",
		"--ulimit", "nofile=4096:4096",
		"-f", "/src/Dockerfile",
		"-t", "quay.io/org/app:1.0",
		"/src",
	}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("buildArgs =\n%v\nwant\n%v", got, want)
	}
}

func TestPushArgs(t *testing.T) {
	o := Options{
		Image:      "quay.io/org/app:1.0",
		TLSVerify:  false,
		DigestFile: "/tmp/digest",
	}
	got := o.pushArgs("quay.io/org/app:run-abc")
	want := []string{
		"push",
		"--tls-verify=false",
		"--retry=5",
		"--digestfile=/tmp/digest",
		"quay.io/org/app:1.0",
		"docker://quay.io/org/app:run-abc",
	}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("pushArgs = %v, want %v", got, want)
	}
}

// recorded is a fake runner: it notes every invocation and plays the roles
// of buildah's side effects (digestfile on push, image listing on images).
type recorded struct {
	calls     [][]string
	digest    string
	imagesOut string
	failOn    string
}

func (r *recorded) install(t *testing.T) {
	t.Helper()
	orig := run
	run = func(dir string, env []string, stdout, stderr io.Writer, name string, args ...string) error {
		call := append([]string{name}, args...)
		r.calls = append(r.calls, call)
		if r.failOn != "" && strings.HasPrefix(strings.Join(call, " "), r.failOn) {
			return fmt.Errorf("injected failure")
		}
		if name == "buildah" && len(args) > 0 && args[0] == "push" {
			for _, a := range args {
				if v, ok := strings.CutPrefix(a, "--digestfile="); ok {
					if err := os.WriteFile(v, []byte(r.digest+"\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
		if name == "buildah" && len(args) > 0 && args[0] == "images" {
			fmt.Fprint(stdout, r.imagesOut)
		}
		return nil
	}
	t.Cleanup(func() { run = orig })
}

func TestBuildSequence(t *testing.T) {
	src := srcRepo(t)
	rec := &recorded{
		digest:    "sha256:abc",
		imagesOut: "quay.io/org/app:1.0@sha256:abc\nregistry/ubi9:latest@sha256:def\n",
	}
	rec.install(t)
	digestFile := filepath.Join(t.TempDir(), "digest")

	res, err := Build(Options{
		Image:       "quay.io/org/app:1.0",
		Dockerfile:  "./Containerfile",
		Context:     ".",
		TLSVerify:   true,
		SourceDir:   src,
		TaskRunName: "run-xyz",
		OCIDir:      "/tmp/files/image",
		DigestFile:  digestFile,
	}, io.Discard, io.Discard)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// Build, primary push, run-unique push, base-image listing, OCI save.
	if len(rec.calls) != 5 {
		t.Fatalf("got %d commands, want 5:\n%s", len(rec.calls), strings.Join(commands(rec), "\n"))
	}
	build := strings.Join(rec.calls[0], " ")
	if !strings.HasPrefix(build, "buildah build ") ||
		!strings.Contains(build, "-f "+filepath.Join(src, "Containerfile")) ||
		!strings.Contains(build, "-t quay.io/org/app:1.0") ||
		!strings.Contains(build, "--tls-verify=true") {
		t.Errorf("build command = %q", build)
	}
	push := strings.Join(rec.calls[1], " ")
	if !strings.HasPrefix(push, "buildah push ") || !strings.Contains(push, "docker://quay.io/org/app:1.0") {
		t.Errorf("primary push = %q", push)
	}
	unique := strings.Join(rec.calls[2], " ")
	if !strings.Contains(unique, "docker://quay.io/org/app:run-xyz") || !strings.Contains(unique, "--digestfile="+digestFile) {
		t.Errorf("unique-tag push = %q", unique)
	}
	listing := strings.Join(rec.calls[3], " ")
	if listing != "buildah images --format {{ .Name }}:{{ .Tag }}@{{ .Digest }}" {
		t.Errorf("listing = %q", listing)
	}
	oci := strings.Join(rec.calls[4], " ")
	if oci != "buildah push quay.io/org/app:1.0 oci:/tmp/files/image" {
		t.Errorf("oci save = %q", oci)
	}

	if res.ImageDigest != "sha256:abc" {
		t.Errorf("ImageDigest = %q", res.ImageDigest)
	}
	if res.ImageURL != "quay.io/org/app:1.0" {
		t.Errorf("ImageURL = %q", res.ImageURL)
	}
	// The built image's own line is filtered out; the base image stays.
	if res.BaseImagesDigest != "registry/ubi9:latest@sha256:def" {
		t.Errorf("BaseImagesDigest = %q", res.BaseImagesDigest)
	}
}

func TestBuildWithoutTaskRunAndOCIDir(t *testing.T) {
	src := srcRepo(t)
	rec := &recorded{digest: "sha256:abc"}
	rec.install(t)

	res, err := Build(Options{
		Image:      "quay.io/org/app:1.0",
		Dockerfile: "./Containerfile",
		SourceDir:  src,
		DigestFile: filepath.Join(t.TempDir(), "digest"),
	}, io.Discard, io.Discard)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	for _, c := range commands(rec) {
		if strings.Contains(c, "run-xyz") || strings.Contains(c, "oci:") {
			t.Errorf("unexpected optional command: %q", c)
		}
	}
	if res.ImageDigest != "sha256:abc" {
		t.Errorf("ImageDigest = %q", res.ImageDigest)
	}
}

func TestBuildFailureStopsTheSequence(t *testing.T) {
	src := srcRepo(t)
	rec := &recorded{failOn: "buildah push"}
	rec.install(t)

	_, err := Build(Options{
		Image:      "quay.io/org/app:1.0",
		Dockerfile: "./Containerfile",
		SourceDir:  src,
		DigestFile: filepath.Join(t.TempDir(), "digest"),
	}, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected the push failure to surface")
	}
	for _, c := range commands(rec) {
		if strings.HasPrefix(c, "buildah images") {
			t.Errorf("sequence continued past the failed push: %q", c)
		}
	}
}

func commands(r *recorded) []string {
	var out []string
	for _, c := range r.calls {
		out = append(out, strings.Join(c, " "))
	}
	return out
}
