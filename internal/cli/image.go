package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/project-lightpath/cli-tools/internal/imagebuild"
)

func newImageCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "image",
		Short: "Build container images from a source checkout",
	}
	cmd.AddCommand(newImageBuildCmd())
	return cmd
}

type imageBuildOpts struct {
	image         string
	dockerfile    string
	context       string
	tlsVerify     bool
	buildArgs     []string
	buildArgsFile string
	labels        string
	storageDriver string
	sourceDir     string
	taskRunName   string
	ociDir        string
	digestFile    string
}

func newImageBuildCmd() *cobra.Command {
	var o imageBuildOpts

	cmd := &cobra.Command{
		Use:   "build",
		Short: "Build an image with buildah and push it",
		Long: `Builds an image from a source checkout with buildah, pushes it to its
registry, and reports the digest.

The image is pushed twice: once to the given reference and once to a
TaskRun-unique tag, so concurrent runs cannot race on the primary tag. The
second push only happens when --task-run-name is set.

Positional arguments after -- are --build-arg values ("arg=value"), so a
Tekton Task can spread an array param over them.`,
		Args: cobra.ArbitraryArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return bindEnv(cmd, map[string]string{
				"image":           "IMAGE",
				"dockerfile":      "DOCKERFILE",
				"context":         "CONTEXT",
				"tls-verify":      "TLSVERIFY",
				"build-args-file": "BUILD_ARGS_FILE",
				"labels":          "LABELS",
				"storage-driver":  "STORAGE_DRIVER",
				"source-dir":      "SOURCE_DIR",
				"task-run-name":   "TASK_RUN_NAME",
				"oci-dir":         "OCI_DIR",
				"digest-file":     "DIGEST_FILE",
			})
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			o.buildArgs = append(o.buildArgs, args...)
			return runImageBuild(cmd, &o)
		},
	}

	f := cmd.Flags()
	f.StringVar(&o.image, "image", "", "reference of the image to produce (required)")
	f.StringVar(&o.dockerfile, "dockerfile", "./Dockerfile",
		"path to the Dockerfile to build, relative to the context")
	f.StringVar(&o.context, "context", ".", "build context, relative to the source directory")
	f.BoolVar(&o.tlsVerify, "tls-verify", true, "verify TLS on the registry endpoint")
	f.StringSliceVar(&o.buildArgs, "build-arg", nil,
		`--build-arg value ("arg=value"); repeatable, and positional arguments after -- count too`)
	f.StringVar(&o.buildArgsFile, "build-args-file", "",
		"file with build arguments, relative to the source directory")
	f.StringVar(&o.labels, "labels", "",
		"newline-separated key=value labels to stamp onto the image (the OCI source and revision annotations belong here)")
	f.StringVar(&o.storageDriver, "storage-driver", "vfs", "buildah storage driver")
	f.StringVar(&o.sourceDir, "source-dir", ".", "directory containing the checked-out source")
	f.StringVar(&o.taskRunName, "task-run-name", "",
		"TaskRun name used for the race-avoiding unique-tag push (empty skips that push)")
	f.StringVar(&o.ociDir, "oci-dir", "",
		"also save the image as an OCI layout in this directory (empty skips the save)")
	f.StringVar(&o.digestFile, "digest-file", "/tmp/tssc-image-digest",
		"where buildah writes the push digest")
	_ = cmd.MarkFlagRequired("image")
	return cmd
}

func runImageBuild(cmd *cobra.Command, o *imageBuildOpts) error {
	res, err := imagebuild.Build(imagebuild.Options{
		Image:         o.image,
		Dockerfile:    o.dockerfile,
		Context:       o.context,
		TLSVerify:     o.tlsVerify,
		BuildArgs:     o.buildArgs,
		BuildArgsFile: o.buildArgsFile,
		Labels:        o.labels,
		StorageDriver: o.storageDriver,
		SourceDir:     o.sourceDir,
		TaskRunName:   o.taskRunName,
		OCIDir:        o.ociDir,
		DigestFile:    o.digestFile,
	}, cmd.OutOrStdout(), cmd.ErrOrStderr())
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "IMAGE_URL=%s\n", res.ImageURL)
	fmt.Fprintf(out, "IMAGE_DIGEST=%s\n", res.ImageDigest)
	if res.BaseImagesDigest != "" {
		fmt.Fprintf(out, "BASE_IMAGES_DIGESTS=%s\n", res.BaseImagesDigest)
	}
	return newResults().WriteAll(map[string]string{
		"IMAGE_DIGEST":        res.ImageDigest,
		"IMAGE_URL":           res.ImageURL,
		"BASE_IMAGES_DIGESTS": res.BaseImagesDigest,
	})
}
