package rhtpa

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type cycloneDXVersion struct {
	major int
	minor int
}

func parseCycloneDXVersion(value string) (cycloneDXVersion, error) {
	major, minor, ok := strings.Cut(value, ".")
	if ok {
		m, majorErr := strconv.Atoi(major)
		n, minorErr := strconv.Atoi(minor)
		if majorErr == nil && minorErr == nil && m > 0 && n >= 0 &&
			fmt.Sprintf("%d.%d", m, n) == value {
			return cycloneDXVersion{major: m, minor: n}, nil
		}
	}
	return cycloneDXVersion{}, fmt.Errorf("invalid CycloneDX version %q, expected major.minor", value)
}

func (v cycloneDXVersion) newerThan(other cycloneDXVersion) bool {
	return v.major > other.major || (v.major == other.major && v.minor > other.minor)
}

// readCycloneDX returns the original bytes for hashing. The quick prefix
// check avoids reading unrelated binary files from large workspaces.
func readCycloneDX(path string) ([]byte, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = file.Close() }()
	reader := bufio.NewReader(file)
	prefix, err := reader.Peek(512)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, "", err
	}
	prefix = bytes.TrimLeft(prefix, " \t\r\n")
	if len(prefix) > 0 && prefix[0] != '{' {
		return nil, "", nil
	}

	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, "", err
	}
	var header struct {
		Format      string          `json:"bomFormat"`
		SpecVersion json.RawMessage `json:"specVersion"`
	}
	if err := json.Unmarshal(content, &header); err != nil || header.Format != "CycloneDX" {
		return nil, "", nil
	}
	var version string
	_ = json.Unmarshal(header.SpecVersion, &version)
	return content, version, nil
}

func convertCycloneDX(ctx context.Context, original []byte, version cycloneDXVersion, log io.Writer) ([]byte, error) {
	format := fmt.Sprintf("cyclonedx-json@%d.%d", version.major, version.minor)
	cmd := exec.CommandContext(ctx, "syft", "convert", "-", "-o", format)
	cmd.Env = append(os.Environ(), "SYFT_CHECK_FOR_APP_UPDATE=false")
	cmd.Stdin = bytes.NewReader(original)
	cmd.Stderr = log
	content, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("syft convert to %s: %w", format, err)
	}
	return content, nil
}

type jsonObject map[string]json.RawMessage

func readObject(content json.RawMessage) (jsonObject, error) {
	var object jsonObject
	if len(content) != 0 {
		if err := json.Unmarshal(content, &object); err != nil {
			return nil, err
		}
	}
	if object == nil {
		object = make(jsonObject)
	}
	return object, nil
}

// withComponentName changes the upload payload and preserves unknown fields
// and exact JSON numbers without rewriting the input file.
func withComponentName(content []byte, name string) ([]byte, error) {
	doc, err := readObject(content)
	if err != nil {
		return nil, err
	}
	meta, err := readObject(doc["metadata"])
	if err != nil {
		return nil, fmt.Errorf("metadata must be a JSON object: %w", err)
	}
	component, err := readObject(meta["component"])
	if err != nil {
		return nil, fmt.Errorf("metadata.component must be a JSON object: %w", err)
	}
	component["name"], err = json.Marshal(name)
	if err != nil {
		return nil, err
	}
	meta["component"], err = json.Marshal(component)
	if err != nil {
		return nil, err
	}
	doc["metadata"], err = json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	return json.Marshal(doc)
}
