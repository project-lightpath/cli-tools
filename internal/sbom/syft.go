package sbom

import (
	"fmt"
	"io"
	"os/exec"
)

// OutputFormat is the syft output format every SBOM this tool writes uses.
//
// CycloneDX 1.6, not 1.5: RHTPA Exploit Intelligence accepts CycloneDX 1.6
// or SPDX 2.3 only, and silently has nothing to work with otherwise. 1.6 is
// a superset here -- RHTPA ingests it the same way, and the
// syft:image:labels:* properties carried over from the image labels are
// identical. This is deliberately not a flag: a per-run choice is one
// misconfigured run away from an SBOM the scanner cannot read.
const OutputFormat = "cyclonedx-json@1.6"

// Scan is one syft invocation: what to scan and where the SBOM goes.
//
// Scheme is restricted to the two the pipeline uses: "dir" for a source
// checkout and "oci-dir" for an OCI image layout on disk. The restriction is
// deliberate -- a typo'd scheme would otherwise be handed to syft as-is, and
// a scheme like "registry" would turn a build step into a network fetch.
type Scan struct {
	Scheme string
	Path   string
	Output string
}

// Args builds the argument vector for the syft invocation.
func (s Scan) Args() []string {
	return []string{
		s.Scheme + ":" + s.Path,
		"--output", OutputFormat + "=" + s.Output,
	}
}

func (s Scan) validate() error {
	switch s.Scheme {
	case "dir", "oci-dir":
	default:
		return fmt.Errorf("unsupported scan scheme %q (want dir or oci-dir)", s.Scheme)
	}
	if s.Path == "" || s.Output == "" {
		return fmt.Errorf("a %s scan needs both a path and an output", s.Scheme)
	}
	return nil
}

// RunScans runs each scan with the syft binary from PATH, in dir.
//
// dir is the working directory syft runs in, which is not necessarily the
// scanned path: syft only picks up a repository's .syft.yaml when started
// from the repository root (anchore/syft#2465), so a caller scanning a
// checkout passes the checkout as dir to keep the repository's syft
// configuration in effect.
func RunScans(scans []Scan, dir string, stdout, stderr io.Writer) error {
	for _, s := range scans {
		if err := s.validate(); err != nil {
			return err
		}
		cmd := exec.Command("syft", s.Args()...)
		cmd.Dir = dir
		cmd.Stdout = stdout
		cmd.Stderr = stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("syft %s:%s: %w", s.Scheme, s.Path, err)
		}
	}
	return nil
}
