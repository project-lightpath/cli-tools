package sbom

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// AddImageLabels adds the OCI layout's config labels to the CycloneDX SBOM
// at sbomPath as syft:image:labels:<name> metadata properties, and rewrites
// the file.
//
// syft wrote those properties itself up to 1.19; newer releases read the
// labels but no longer encode them, and RHTPA Exploit Intelligence reads
// org.opencontainers.image.source/revision from them. The injection is
// idempotent, and a layout whose image config carries no labels is a no-op.
func AddImageLabels(sbomPath, layoutDir string) error {
	labels, err := imageLabels(layoutDir)
	if err != nil {
		return err
	}
	if len(labels) == 0 {
		return nil
	}

	doc, err := os.ReadFile(sbomPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", sbomPath, err)
	}
	fields, err := decodeDocument(doc, "image SBOM")
	if err != nil {
		return err
	}

	type property struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	// Decoded only as far as the properties; the rest of metadata survives
	// byte for byte.
	var metadata struct {
		Properties []property `json:"properties"`
	}
	rawMetadata, ok := fields["metadata"]
	if !ok {
		return fmt.Errorf("image SBOM has no metadata block to attach labels to")
	}
	if err := json.Unmarshal(rawMetadata, &metadata); err != nil {
		return fmt.Errorf("parsing image SBOM metadata: %w", err)
	}

	present := map[string]bool{}
	for _, p := range metadata.Properties {
		present[p.Name] = true
	}
	names := make([]string, 0, len(labels))
	for name := range labels {
		names = append(names, name)
	}
	sort.Strings(names) // deterministic output regardless of map order
	added := 0
	for _, name := range names {
		if present["syft:image:labels:"+name] {
			continue
		}
		metadata.Properties = append(metadata.Properties,
			property{Name: "syft:image:labels:" + name, Value: labels[name]})
		added++
	}
	if added == 0 {
		return nil
	}

	raw, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("re-encoding image SBOM metadata: %w", err)
	}
	fields["metadata"] = raw

	compact, err := json.Marshal(fields)
	if err != nil {
		return fmt.Errorf("re-encoding image SBOM: %w", err)
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, compact, "", "    "); err != nil {
		return fmt.Errorf("re-indenting image SBOM: %w", err)
	}

	// Keep the permissions the scan wrote the file with.
	perm := os.FileMode(0o644)
	if info, err := os.Stat(sbomPath); err == nil {
		perm = info.Mode().Perm()
	}
	if err := os.WriteFile(sbomPath, buf.Bytes(), perm); err != nil {
		return fmt.Errorf("writing %s: %w", sbomPath, err)
	}
	return nil
}

// imageLabels walks an OCI image layout and returns the config labels of
// the first image it finds. Per-arch manifests are expected to share
// labels, so the first one with any decides.
func imageLabels(layoutDir string) (map[string]string, error) {
	raw, err := os.ReadFile(filepath.Join(layoutDir, "index.json"))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", filepath.Join(layoutDir, "index.json"), err)
	}
	var index struct {
		Manifests []struct {
			Digest string `json:"digest"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(raw, &index); err != nil {
		return nil, fmt.Errorf("parsing index.json: %w", err)
	}
	for _, m := range index.Manifests {
		labels, err := labelsFromDescriptor(layoutDir, m.Digest)
		if err != nil {
			return nil, err
		}
		if len(labels) > 0 {
			return labels, nil
		}
	}
	return nil, nil
}

// labelsFromDescriptor resolves one descriptor digest to its blob and, if
// it is a manifest, returns the labels from its config. An index descriptor
// is followed into via its first manifest.
func labelsFromDescriptor(layoutDir, digest string) (map[string]string, error) {
	blob, err := os.ReadFile(blobPath(layoutDir, digest))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", blobPath(layoutDir, digest), err)
	}
	var manifest struct {
		Manifests []struct {
			Digest string `json:"digest"`
		} `json:"manifests"`
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
	}
	if err := json.Unmarshal(blob, &manifest); err != nil {
		return nil, fmt.Errorf("parsing manifest %s: %w", digest, err)
	}
	if manifest.Config.Digest != "" {
		config, err := os.ReadFile(blobPath(layoutDir, manifest.Config.Digest))
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", blobPath(layoutDir, manifest.Config.Digest), err)
		}
		var image struct {
			Config struct {
				Labels map[string]string `json:"Labels"`
			} `json:"config"`
		}
		if err := json.Unmarshal(config, &image); err != nil {
			return nil, fmt.Errorf("parsing image config %s: %w", manifest.Config.Digest, err)
		}
		return image.Config.Labels, nil
	}
	if len(manifest.Manifests) > 0 {
		return labelsFromDescriptor(layoutDir, manifest.Manifests[0].Digest)
	}
	return nil, nil
}

// blobPath maps a descriptor digest to its file in the layout's blob store.
func blobPath(layoutDir, digest string) string {
	algo, hex, found := strings.Cut(digest, ":")
	if !found {
		return filepath.Join(layoutDir, "blobs", "sha256", digest)
	}
	return filepath.Join(layoutDir, "blobs", algo, hex)
}
