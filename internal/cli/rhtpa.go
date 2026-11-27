package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/project-lightpath/cli-tools/internal/rhtpa"
	"github.com/project-lightpath/cli-tools/internal/tekton"
)

func newRHTPACmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rhtpa",
		Short: "Work with Red Hat Trusted Profile Analyzer and Trustification",
	}
	cmd.AddCommand(newUploadSBOMCmd())
	return cmd
}

func newUploadSBOMCmd() *cobra.Command {
	var opts rhtpa.UploadOptions

	cmd := &cobra.Command{
		Use:   "upload-sbom",
		Short: "Upload CycloneDX JSON SBOMs to RHTPA or Trustification",
		Args:  cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return bindEnv(cmd, map[string]string{
				"component":              "COMPONENT_NAME",
				"sboms-dir":              "SBOMS_DIR",
				"secret-dir":             "TRUSTIFICATION_SECRET_PATH",
				"fail-if-not-configured": "FAIL_IF_TRUSTIFICATION_NOT_CONFIGURED",
				"http-retries":           "HTTP_RETRIES",
				"ca-bundle":              "TPA_CA_BUNDLE",
				"console-url":            "TPA_CONSOLE_URL",
				"results-dir":            "TEKTON_RESULTS_DIR",
			})
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			link, err := rhtpa.UploadSBOMs(cmd.Context(), opts, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			dir, err := cmd.Flags().GetString("results-dir")
			if err != nil {
				return err
			}
			if err := tekton.NewResults(dir).Write("TPA_SBOM_URL", link); err != nil {
				return err
			}
			if link == "" {
				return nil
			}
			payload, err := json.Marshal(map[string]string{"TPA_SBOM_URL": link})
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "TPA_SBOM_URL_EYECATCHER_BEGIN\n%s\nTPA_SBOM_URL_EYECATCHER_END\n", payload)
			return err
		},
	}

	f := cmd.Flags()
	f.StringVar(&opts.Component, "component", "", "component name to set in each uploaded SBOM (required)")
	f.StringVar(&opts.SBOMsDir, "sboms-dir", ".", "directory to search recursively for CycloneDX JSON SBOMs")
	f.StringVar(&opts.SecretDir, "secret-dir", "/run/secrets/trustification", "directory containing the Trustification or RHTPA Secret keys")
	f.BoolVar(&opts.FailIfNotConfigured, "fail-if-not-configured", true, "fail when required Secret keys are missing or empty")
	f.IntVar(&opts.HTTPRetries, "http-retries", 3, "number of retries after a transient HTTP failure")
	f.StringVar(&opts.CABundle, "ca-bundle", "", "additional CA bundle (defaults to the mounted Tekton CA bundle when present)")
	f.StringVar(&opts.ConsoleURL, "console-url", "", "console base URL (overrides the Secret's console_url)")

	_ = cmd.MarkFlagRequired("component")
	return cmd
}
