package rhtpa

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/project-lightpath/cli-tools/internal/tekton"
)

type client struct {
	http      *http.Client
	config    config
	retries   int
	tokenURL  *url.URL
	token     string
	refreshAt time.Time
}

func newClient(cfg config, caBundle string, retries int) (*client, error) {
	roots, err := tekton.RootCAs(caBundle)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if roots != nil {
		transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	return &client{
		http: &http.Client{
			Transport: transport,
			Timeout:   2 * time.Minute,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		config:  cfg,
		retries: retries,
	}, nil
}

func (c *client) discover(ctx context.Context) (*url.URL, error) {
	discoveryURL := c.config.issuerURL.JoinPath(".well-known", "openid-configuration")
	body, err := c.request(ctx, "OIDC discovery", func() (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL.String(), nil)
	})
	if err != nil {
		return nil, err
	}
	var metadata struct {
		TokenEndpoint string `json:"token_endpoint"`
	}
	if err := json.Unmarshal(body, &metadata); err != nil {
		return nil, fmt.Errorf("OIDC discovery returned invalid JSON: %w", err)
	}
	endpoint, err := parseURL(metadata.TokenEndpoint, "OIDC token_endpoint", true)
	if err != nil {
		return nil, err
	}
	if c.config.issuerURL.Scheme == "https" && endpoint.Scheme != "https" {
		return nil, errors.New("OIDC discovery returned an insecure token endpoint for an HTTPS issuer")
	}
	return endpoint, nil
}

func (c *client) accessToken(ctx context.Context) (string, error) {
	if c.token != "" && (c.refreshAt.IsZero() || time.Now().Before(c.refreshAt)) {
		return c.token, nil
	}
	if c.tokenURL == nil {
		endpoint, err := c.discover(ctx)
		if err != nil {
			return "", err
		}
		c.tokenURL = endpoint
	}

	var started time.Time
	body, err := c.request(ctx, "OIDC token request", func() (*http.Request, error) {
		started = time.Now()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL.String(),
			strings.NewReader("grant_type=client_credentials"))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(c.config.clientID, c.config.clientSecret)
		return req, nil
	})
	if err != nil {
		return "", err
	}
	var token struct {
		AccessToken string      `json:"access_token"`
		TokenType   string      `json:"token_type"`
		ExpiresIn   json.Number `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &token); err != nil {
		return "", errors.New("OIDC token endpoint returned an invalid token response")
	}
	if token.AccessToken == "" || strings.ContainsAny(token.AccessToken, " \t\r\n") {
		return "", errors.New("OIDC token endpoint did not return a valid access_token")
	}
	if token.TokenType != "" && !strings.EqualFold(token.TokenType, "Bearer") {
		return "", errors.New("OIDC token endpoint did not return a bearer token")
	}
	c.token = token.AccessToken
	c.refreshAt = time.Time{}
	if seconds, err := token.ExpiresIn.Int64(); err == nil && seconds > 0 &&
		seconds <= int64(math.MaxInt64/time.Second) {
		ttl := time.Duration(seconds) * time.Second
		c.refreshAt = started.Add(ttl - min(ttl/10, 30*time.Second))
	}
	return c.token, nil
}

func (c *client) upload(ctx context.Context, id string, content []byte) ([]byte, error) {
	endpoint := c.config.apiURL.JoinPath("api", "v3", "sbom")
	endpoint.RawQuery = url.Values{"id": {id}}.Encode()
	token, err := c.accessToken(ctx)
	if err != nil {
		return nil, err
	}
	newRequest := func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(content))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		// The legacy BOMbastic request uses chunked encoding over HTTP/1.1.
		req.ContentLength = -1
		return req, nil
	}

	body, err := c.request(ctx, "SBOM upload", newRequest)
	var status *httpStatusError
	if errors.As(err, &status) && status.code == http.StatusUnauthorized {
		c.token = ""
		token, err = c.accessToken(ctx)
		if err != nil {
			return nil, err
		}
		return c.request(ctx, "SBOM upload", newRequest)
	}
	return body, err
}

type httpStatusError struct {
	code       int
	retryAfter string
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("HTTP %d %s", e.code, http.StatusText(e.code))
}

func (c *client) request(ctx context.Context, operation string, makeRequest func() (*http.Request, error)) ([]byte, error) {
	delay := time.Second
	for attempt := 0; ; attempt++ {
		req, err := makeRequest()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", operation, err)
		}
		body, err := c.send(req)
		if err == nil {
			return body, nil
		}
		retry, retryAfter := retryable(err)
		if !retry || attempt >= c.retries || ctx.Err() != nil {
			return nil, fmt.Errorf("%s: %w", operation, err)
		}
		timer := time.NewTimer(max(delay, retryAfter))
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
			delay = min(2*delay, 30*time.Second)
		}
	}
}

func (c *client) send(req *http.Request) ([]byte, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &httpStatusError{code: resp.StatusCode, retryAfter: resp.Header.Get("Retry-After")}
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

func retryable(err error) (bool, time.Duration) {
	var status *httpStatusError
	if errors.As(err, &status) {
		switch status.code {
		case 408, 429, 500, 502, 503, 504:
			return true, retryAfterDelay(status.retryAfter)
		default:
			return false, 0
		}
	}
	var netErr net.Error
	return (errors.As(err, &netErr) && netErr.Timeout()) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE), 0
}

func retryAfterDelay(value string) time.Duration {
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds >= 0 &&
		seconds <= int64(math.MaxInt64/time.Second) {
		return time.Duration(seconds) * time.Second
	}
	if when, err := http.ParseTime(value); err == nil {
		return time.Until(when)
	}
	return 0
}
