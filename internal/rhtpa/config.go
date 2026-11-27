package rhtpa

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

var errMissingConfig = errors.New("missing or empty Secret keys")

type config struct {
	apiURL       *url.URL
	issuerURL    *url.URL
	consoleURL   *url.URL
	clientID     string
	clientSecret string
	maxCycloneDX *cycloneDXVersion
}

func loadConfig(dir, consoleOverride string) (config, error) {
	var missing []string
	values := make(map[string]string)
	for _, key := range []string{"bombastic_api_url", "oidc_issuer_url", "oidc_client_id", "oidc_client_secret"} {
		value, err := readSecretKey(dir, key)
		if err != nil {
			return config{}, err
		}
		if strings.TrimSpace(value) == "" {
			missing = append(missing, key)
		}
		values[key] = value
	}
	if len(missing) > 0 {
		return config{}, fmt.Errorf("%s: %w: %s", dir, errMissingConfig, strings.Join(missing, ", "))
	}

	apiURL, err := parseURL(values["bombastic_api_url"], "bombastic_api_url", false)
	if err != nil {
		return config{}, err
	}
	issuerURL, err := parseURL(values["oidc_issuer_url"], "oidc_issuer_url", false)
	if err != nil {
		return config{}, err
	}
	cfg := config{
		apiURL:       apiURL,
		issuerURL:    issuerURL,
		clientID:     values["oidc_client_id"],
		clientSecret: values["oidc_client_secret"],
	}

	maxVersion, err := readSecretKey(dir, "supported_cyclonedx_version")
	if err != nil {
		return config{}, err
	}
	if maxVersion = strings.TrimSpace(maxVersion); maxVersion != "" {
		version, err := parseCycloneDXVersion(maxVersion)
		if err != nil {
			return config{}, fmt.Errorf("supported_cyclonedx_version: %w", err)
		}
		cfg.maxCycloneDX = &version
	}

	console := strings.TrimSpace(consoleOverride)
	if console == "" {
		console, err = readSecretKey(dir, "console_url")
		if err != nil {
			return config{}, err
		}
	}
	if strings.TrimSpace(console) != "" {
		cfg.consoleURL, err = parseURL(console, "console_url", false)
		if err != nil {
			return config{}, err
		}
	}
	return cfg, nil
}

func readSecretKey(dir, key string) (string, error) {
	value, err := os.ReadFile(filepath.Join(dir, key))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read Secret key %s: %w", key, err)
	}
	return strings.TrimRight(string(value), "\r\n"), nil
}

func parseURL(raw, name string, allowQuery bool) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") ||
		u.Hostname() == "" || u.User != nil || u.Fragment != "" ||
		(!allowQuery && (u.RawQuery != "" || u.ForceQuery)) {
		return nil, fmt.Errorf("%s must be an absolute HTTP or HTTPS URL without credentials or a fragment", name)
	}
	return u, nil
}
