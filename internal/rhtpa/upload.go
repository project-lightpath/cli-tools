// Package rhtpa uploads CycloneDX SBOMs to RHTPA and Trustification.
package rhtpa

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

// UploadOptions holds the inputs shared by both upload tasks.
type UploadOptions struct {
	Component           string
	SBOMsDir            string
	SecretDir           string
	FailIfNotConfigured bool
	HTTPRetries         int
	CABundle            string
	ConsoleURL          string
}

// UploadSBOMs reports each successful upload and returns the link for the
// final SBOM in digest order, as the original tasks did.
func UploadSBOMs(ctx context.Context, opts UploadOptions, log io.Writer) (string, error) {
	if opts.HTTPRetries < 0 {
		return "", errors.New("--http-retries must be non-negative")
	}

	var api *client
	var lastID, lastURL string
	seen := make(map[string]bool)
	dir := filepath.Clean(opts.SBOMsDir)
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if path == dir && !entry.IsDir() {
			return fmt.Errorf("%s: expected an SBOM directory", path)
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		original, specVersion, err := readCycloneDX(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		if original == nil {
			return nil
		}

		id := fmt.Sprintf("sha256:%x", sha256.Sum256(original))
		if seen[id] {
			return nil
		}
		seen[id] = true

		// Resolve configuration only once an SBOM is found. An empty
		// workspace needs neither credentials nor network access.
		if api == nil {
			cfg, err := loadConfig(opts.SecretDir, opts.ConsoleURL)
			if errors.Is(err, errMissingConfig) && !opts.FailIfNotConfigured {
				fmt.Fprintf(log, "Skipping SBOM upload: %v\n", err)
				return fs.SkipAll
			}
			if err != nil {
				return err
			}
			api, err = newClient(cfg, opts.CABundle, opts.HTTPRetries)
			if err != nil {
				return err
			}
		}

		content := original
		if maxVersion := api.config.maxCycloneDX; maxVersion != nil {
			version, err := parseCycloneDXVersion(specVersion)
			if err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
			if version.newerThan(*maxVersion) {
				fmt.Fprintf(log, "Converting %q from CycloneDX %s to %d.%d\n",
					path, specVersion, maxVersion.major, maxVersion.minor)
				content, err = convertCycloneDX(ctx, original, *maxVersion, log)
				if err != nil {
					return fmt.Errorf("%s: %w", path, err)
				}
			}
		}
		content, err = withComponentName(content, opts.Component)
		if err != nil {
			return fmt.Errorf("set component name in %s: %w", path, err)
		}

		response, err := api.upload(ctx, id, content)
		if err != nil {
			return fmt.Errorf("%s (%s): %w", path, id, err)
		}
		link := sbomURL(api.config, id, response)
		fmt.Fprintf(log, "Uploaded %q (%s): %s\n", path, id, link)
		if id > lastID {
			lastID, lastURL = id, link
		}
		return nil
	})
	if api != nil {
		api.http.CloseIdleConnections()
	}
	if err != nil {
		return "", err
	}
	if len(seen) == 0 {
		fmt.Fprintf(log, "No CycloneDX SBOMs to upload in %q\n", dir)
	}
	return lastURL, nil
}

var uuidID = regexp.MustCompile(`^(urn:uuid:)?[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$`)

func sbomURL(cfg config, legacyID string, response []byte) string {
	var result struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(response, &result) == nil && uuidID.MatchString(result.ID) {
		// Trustify returns the ID of the ingested document. Its UI is
		// served at the API host unless a separate console is configured.
		base := cfg.apiURL
		if cfg.consoleURL != nil {
			base = cfg.consoleURL
		}
		return base.JoinPath("sboms", escapedID(result.ID)).String()
	}

	base := cfg.consoleURL
	if base == nil {
		legacyBase := *cfg.apiURL
		host := legacyBase.Hostname()
		if host == "sbom" || strings.HasPrefix(host, "sbom.") || strings.HasPrefix(host, "sbom-") {
			legacyBase.Host = "console" + strings.TrimPrefix(legacyBase.Host, "sbom")
		}
		base = &legacyBase
	}
	return base.JoinPath("sbom", "content", escapedID(legacyID)).String()
}

func escapedID(id string) string {
	// Escape colons for compatibility with links emitted by the old tasks.
	return strings.ReplaceAll(url.PathEscape(id), ":", "%3A")
}
