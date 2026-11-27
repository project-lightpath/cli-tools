package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/project-lightpath/cli-tools/internal/sbom"
)

func newSbomCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sbom",
		Short: "Generate and merge CycloneDX SBOMs",
	}
	cmd.AddCommand(newSbomGenerateCmd(), newSbomMergeCmd())
	return cmd
}

type sbomGenerateOpts struct {
	dir    string
	ociDir string
	dirOut string
	ociOut string
	cwd    string
}

func newSbomGenerateCmd() *cobra.Command {
	var o sbomGenerateOpts

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate CycloneDX 1.6 SBOMs with syft",
		Long: `Runs syft over a source directory and/or an OCI image layout,
writing one CycloneDX 1.6 JSON SBOM per scan.

The output format is not configurable: RHTPA accepts CycloneDX 1.6 or SPDX
2.3 only, and syft's default of 1.5 leaves it with nothing to work with.

After an --oci-dir scan, the image's config labels are added to the SBOM as
syft:image:labels:<name> metadata properties -- newer syft releases stopped
writing them, and RHTPA reads org.opencontainers.image.source/revision from
them.`,
		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return bindEnv(cmd, map[string]string{
				"dir":        "SCAN_DIR",
				"oci-dir":    "SCAN_OCI_DIR",
				"dir-output": "SOURCE_SBOM",
				"oci-output": "IMAGE_SBOM",
				"cwd":        "SYFT_CWD",
			})
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := runSbomGenerate(cmd, &o); err != nil {
				return err
			}
			// Restore the image labels syft no longer writes into its
			// CycloneDX output; see AddImageLabels.
			if o.ociDir != "" {
				if err := sbom.AddImageLabels(o.ociOut, o.ociDir); err != nil {
					return err
				}
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&o.dir, "dir", "", "source directory to scan")
	f.StringVar(&o.ociDir, "oci-dir", "", "OCI image layout directory to scan")
	f.StringVar(&o.dirOut, "dir-output", "sbom-source.json",
		"where the source scan's SBOM goes")
	f.StringVar(&o.ociOut, "oci-output", "sbom-image.json",
		"where the image scan's SBOM goes")
	f.StringVar(&o.cwd, "cwd", "",
		"working directory for syft (default: the --dir path when set, else the current directory; a repository's .syft.yaml is only read from the working directory)")
	return cmd
}

func runSbomGenerate(cmd *cobra.Command, o *sbomGenerateOpts) error {
	if o.dir == "" && o.ociDir == "" {
		return fmt.Errorf("nothing to scan: pass --dir and/or --oci-dir")
	}
	var scans []sbom.Scan
	if o.dir != "" {
		scans = append(scans, sbom.Scan{Scheme: "dir", Path: o.dir, Output: o.dirOut})
	}
	if o.ociDir != "" {
		scans = append(scans, sbom.Scan{Scheme: "oci-dir", Path: o.ociDir, Output: o.ociOut})
	}
	cwd := o.cwd
	if cwd == "" {
		// Run syft from the scanned checkout so a repository's .syft.yaml
		// stays in effect (anchore/syft#2465).
		cwd = o.dir
	}
	return sbom.RunScans(scans, cwd, cmd.OutOrStdout(), cmd.ErrOrStderr())
}

type sbomMergeOpts struct {
	imageSBOM  string
	sourceSBOM string
	image      string
	output     string
	sbomsDir   string
}

func newSbomMergeCmd() *cobra.Command {
	var o sbomMergeOpts

	cmd := &cobra.Command{
		Use:   "merge",
		Short: "Merge source and image SBOMs into one CycloneDX document",
		Long: `Merges the SBOM of a source checkout into the SBOM of the image built
from it, deduplicating components by purl, and writes the merged document.

The output goes to --output and, when --sboms-dir is set, a copy named
sbom-cyclonedx.json lands there too -- that fixed name is what the
downstream tasks consume. The SBOM_BLOB_URL Tekton result records where the
merged SBOM would live as a registry blob.`,
		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return bindEnv(cmd, map[string]string{
				"image-sbom":  "IMAGE_SBOM",
				"source-sbom": "SOURCE_SBOM",
				"image":       "IMAGE",
				"output":      "SBOM_OUTPUT",
				"sboms-dir":   "SBOMS_DIR",
			})
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSbomMerge(cmd, &o)
		},
	}

	f := cmd.Flags()
	f.StringVar(&o.imageSBOM, "image-sbom", "sbom-image.json", "path to the image SBOM")
	f.StringVar(&o.sourceSBOM, "source-sbom", "sbom-source.json", "path to the source SBOM")
	f.StringVar(&o.image, "image", "", "image reference the SBOMs describe (required)")
	f.StringVar(&o.output, "output", "sbom-cyclonedx.json", "where the merged SBOM goes")
	f.StringVar(&o.sbomsDir, "sboms-dir", "",
		"also copy the merged SBOM here as sbom-cyclonedx.json")
	_ = cmd.MarkFlagRequired("image")
	return cmd
}

func runSbomMerge(cmd *cobra.Command, o *sbomMergeOpts) error {
	imageDoc, err := os.ReadFile(o.imageSBOM)
	if err != nil {
		return fmt.Errorf("reading image SBOM: %w", err)
	}
	sourceDoc, err := os.ReadFile(o.sourceSBOM)
	if err != nil {
		return fmt.Errorf("reading source SBOM: %w", err)
	}

	merged, err := sbom.Merge(imageDoc, sourceDoc)
	if err != nil {
		return err
	}
	if err := os.WriteFile(o.output, merged, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", o.output, err)
	}
	if o.sbomsDir != "" {
		if err := os.MkdirAll(o.sbomsDir, 0o755); err != nil {
			return fmt.Errorf("creating %s: %w", o.sbomsDir, err)
		}
		copy := filepath.Join(o.sbomsDir, "sbom-cyclonedx.json")
		if err := os.WriteFile(copy, merged, 0o644); err != nil {
			return fmt.Errorf("writing %s: %w", copy, err)
		}
	}

	url := sbom.BlobURL(o.image, merged)
	fmt.Fprintln(cmd.OutOrStdout(), url)
	return newResults().Write("SBOM_BLOB_URL", url)
}
