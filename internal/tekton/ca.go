package tekton

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// RootCAs adds a PEM bundle to the system roots. An empty path uses the
// optional Tekton mount and returns nil when the mount is absent.
func RootCAs(path string) (*x509.CertPool, error) {
	required := path != ""
	if !required {
		path = CABundlePath
	}
	pem, err := os.ReadFile(path)
	if !required && errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read CA bundle %s: %w", path, err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("load system CA roots: %w", err)
	}
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("CA bundle %s contains no valid certificates", path)
	}
	return roots, nil
}
