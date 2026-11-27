// Package cli wires the subcommands of the tssc binary.
//
// One binary, many subcommands, one container image. Separate binaries would
// each statically link their own copy of the whole dependency tree, so the
// image would carry the HTTP stack and every SDK once per tool.
package cli

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/project-lightpath/cli-tools/internal/version"
)

// NewRootCmd builds the command tree.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:          "tssc",
		Short:        "Supply-chain security tools for the TSSC pipelines",
		Version:      version.String(),
		SilenceUsage: true, // a runtime failure is not a usage error
		// main prints the error; without this cobra prints it too.
		SilenceErrors: true,
	}

	root.PersistentFlags().String("results-dir", "",
		"directory to write Tekton results into (default: /tekton/results when it exists, otherwise results are not written)")

	root.AddCommand(
		newBumpCmd(),
		newRHTPACmd(),
	)
	return root
}

// Execute runs the command tree, dispatching on argv[0] first so the image can
// expose busybox-style symlinks (/usr/bin/rhtpa-analyze -> tssc) for callers
// that want a single-purpose command name.
func Execute() error {
	root := NewRootCmd()

	if sub, ok := argv0Alias(os.Args[0]); ok {
		root.SetArgs(append(sub, os.Args[1:]...))
	}
	return root.Execute()
}

// argv0Aliases maps a symlink name to the subcommand path it stands for. Each
// entry needs a matching symlink in the Containerfile.
var argv0Aliases = map[string][]string{}

func argv0Alias(arg0 string) ([]string, bool) {
	name := strings.TrimSuffix(filepath.Base(arg0), ".exe")
	sub, ok := argv0Aliases[name]
	return sub, ok
}
