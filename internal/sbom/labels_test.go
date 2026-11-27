package sbom

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixtures are hand-rolled OCI layouts: index.json pointing at a
// manifest blob pointing at a config blob with Labels, the same shape
// buildah and skopeo write. The cases mirror what AddImageLabels exists
// for: syft 1.19 wrote these properties itself, newer releases do not.

// writeLayout writes an OCI layout whose image config carries labels.
// Nil labels write a config without any; nested wraps the manifest one
// level deeper in an index, the shape a multi-arch layout has.
func writeLayout(t *testing.T, labels map[string]string, nested bool) string {
	t.Helper()
	dir := t.TempDir()
	blobs := filepath.Join(dir, "blobs", "sha256")
	if err := os.MkdirAll(blobs, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name string, v any) string {
		t.Helper()
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(blobs, name)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return "sha256:" + name
	}

	configDigest := write("config", map[string]any{
		"architecture": "amd64",
		"config":       map[string]any{"Labels": labels},
	})
	manifestDigest := write("manifest", map[string]any{
		"mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config":    map[string]any{"digest": configDigest},
	})
	top := manifestDigest
	if nested {
		top = write("index", map[string]any{
			"mediaType": "application/vnd.oci.image.index.v1+json",
			"manifests": []any{map[string]any{"digest": manifestDigest}},
		})
	}
	index := map[string]any{"manifests": []any{map[string]any{"digest": top}}}
	b, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func writeSbom(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "sbom.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func properties(t *testing.T, sbomPath string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(sbomPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Metadata struct {
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("SBOM is not valid JSON: %v", err)
	}
	out := map[string]string{}
	for _, p := range doc.Metadata.Properties {
		out[p.Name] = p.Value
	}
	return out
}

func TestAddImageLabelsAddsProperties(t *testing.T) {
	layout := writeLayout(t, map[string]string{
		"org.opencontainers.image.source":   "https://github.com/org/app",
		"org.opencontainers.image.revision": "83b6f93",
	}, false)
	dir := t.TempDir()
	sbomPath := writeSbom(t, dir, `{"bomFormat":"CycloneDX","specVersion":"1.6",`+
		`"metadata":{"component":{"type":"container","name":"x"}},"components":[]}`)

	if err := AddImageLabels(sbomPath, layout); err != nil {
		t.Fatalf("AddImageLabels: %v", err)
	}
	props := properties(t, sbomPath)
	if got := props["syft:image:labels:org.opencontainers.image.source"]; got != "https://github.com/org/app" {
		t.Errorf("source label = %q, want the image config value", got)
	}
	if got := props["syft:image:labels:org.opencontainers.image.revision"]; got != "83b6f93" {
		t.Errorf("revision label = %q, want the image config value", got)
	}
}

func TestAddImageLabelsKeepsExistingMetadata(t *testing.T) {
	layout := writeLayout(t, map[string]string{"a": "1"}, false)
	dir := t.TempDir()
	sbomPath := writeSbom(t, dir, `{"bomFormat":"CycloneDX","specVersion":"1.6",`+
		`"metadata":{"timestamp":"2026-11-27T00:00:00Z","properties":[{"name":"syft:distro:id","value":"rhel"}]},`+
		`"components":[{"type":"library","name":"keep"}]}`)

	if err := AddImageLabels(sbomPath, layout); err != nil {
		t.Fatalf("AddImageLabels: %v", err)
	}
	props := properties(t, sbomPath)
	if props["syft:distro:id"] != "rhel" {
		t.Errorf("pre-existing property was dropped: %v", props)
	}
	if props["syft:image:labels:a"] != "1" {
		t.Errorf("label property missing: %v", props)
	}
	b, _ := os.ReadFile(sbomPath)
	if !strings.Contains(string(b), `"keep"`) {
		t.Error("components were dropped from the SBOM")
	}
}

func TestAddImageLabelsIsIdempotent(t *testing.T) {
	layout := writeLayout(t, map[string]string{"a": "1"}, false)
	dir := t.TempDir()
	sbomPath := writeSbom(t, dir, `{"bomFormat":"CycloneDX","specVersion":"1.6",`+
		`"metadata":{"properties":[{"name":"syft:image:labels:a","value":"1"}]},"components":[]}`)

	if err := AddImageLabels(sbomPath, layout); err != nil {
		t.Fatalf("AddImageLabels: %v", err)
	}
	props := properties(t, sbomPath)
	if len(props) != 1 {
		t.Errorf("properties = %v, want the single existing entry untouched", props)
	}
}

func TestAddImageLabelsFollowsNestedIndex(t *testing.T) {
	layout := writeLayout(t, map[string]string{"a": "1"}, true)
	dir := t.TempDir()
	sbomPath := writeSbom(t, dir, `{"bomFormat":"CycloneDX","specVersion":"1.6",`+
		`"metadata":{"component":{"type":"container","name":"x"}},"components":[]}`)

	if err := AddImageLabels(sbomPath, layout); err != nil {
		t.Fatalf("AddImageLabels: %v", err)
	}
	if got := properties(t, sbomPath)["syft:image:labels:a"]; got != "1" {
		t.Errorf("label property = %q, want it found through the index", got)
	}
}

func TestAddImageLabelsWithoutLabelsIsNoop(t *testing.T) {
	layout := writeLayout(t, nil, false)
	dir := t.TempDir()
	original := `{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{},"components":[]}`
	sbomPath := writeSbom(t, dir, original)

	if err := AddImageLabels(sbomPath, layout); err != nil {
		t.Fatalf("AddImageLabels: %v", err)
	}
	b, _ := os.ReadFile(sbomPath)
	if string(b) != original {
		t.Error("SBOM without labels in the layout should be rewritten to the same content")
	}
}
