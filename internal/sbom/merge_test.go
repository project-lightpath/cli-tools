package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// The cases mirror the behaviors of the merge-sboms Python step this ports,
// including the ones that only show up with real syft output: purl
// deduplication, no-purl passthrough, and the fixed sort key.

func comp(name, purl string) string {
	c := map[string]any{"type": "library", "name": name}
	if purl != "" {
		c["purl"] = purl
	}
	b, _ := json.Marshal(c)
	return string(b)
}

func doc(components ...string) []byte {
	body := "[" + strings.Join(components, ",") + "]"
	return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":` + body + `}`)
}

// names returns the merged document's component names in order.
func names(t *testing.T, merged []byte) []string {
	t.Helper()
	var d struct {
		Components []struct {
			Name string `json:"name"`
		} `json:"components"`
	}
	if err := json.Unmarshal(merged, &d); err != nil {
		t.Fatalf("merged output is not valid JSON: %v", err)
	}
	var out []string
	for _, c := range d.Components {
		out = append(out, c.Name)
	}
	return out
}

func TestMergeDedupesByPurl(t *testing.T) {
	image := doc(comp("jackson", "pkg:maven/jackson"), comp("snakeyaml", "pkg:maven/snakeyaml"))
	source := doc(
		comp("snakeyaml-dup", "pkg:maven/snakeyaml"), // already in the image SBOM
		comp("woodstox", "pkg:maven/woodstox"),
	)
	merged, err := Merge(image, source)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	got := names(t, merged)
	want := []string{"jackson", "snakeyaml", "woodstox"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("merged components = %v, want %v", got, want)
	}
}

func TestMergeDedupesWithinSource(t *testing.T) {
	// The same purl twice inside the source SBOM: only the first survives,
	// like the Python original's growing existing_purls list.
	source := doc(comp("first", "pkg:maven/dup"), comp("second", "pkg:maven/dup"))
	merged, err := Merge(doc(), source)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if got := names(t, merged); strings.Join(got, ",") != "first" {
		t.Errorf("merged components = %v, want [first]", got)
	}
}

func TestMergeKeepsComponentsWithoutPurl(t *testing.T) {
	// Operating-system components carry no purl and are never deduplicated.
	image := doc(comp("glibc", ""))
	source := doc(comp("openssl-libs", ""))
	merged, err := Merge(image, source)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if got := names(t, merged); strings.Join(got, ",") != "glibc,openssl-libs" {
		t.Errorf("merged components = %v, want both", got)
	}
}

func TestMergeSortsByTypeThenName(t *testing.T) {
	image := []byte(`{"components":[
		{"type":"operating-system","name":"ubi9"},
		{"type":"library","name":"zlib"},
		{"type":"framework","name":"spring"}
	]}`)
	source := []byte(`{"components":[
		{"type":"container","name":"app"},
		{"type":"library","name":"woodstox"}
	]}`)
	merged, err := Merge(image, source)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	// Sort key is type+name concatenated, exactly like the Python key
	// lambda -- which is why "operating-system/ubi9" sorts after
	// "library/zlib" here.
	want := []string{"app", "spring", "woodstox", "zlib", "ubi9"}
	if got := names(t, merged); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("merged components = %v, want %v", got, want)
	}
}

func TestMergePreservesUnknownFields(t *testing.T) {
	image := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"serialNumber": "urn:uuid:1234",
		"metadata": {"tools": {"syft": "1.19.0"}},
		"components": [{"type": "library", "name": "jackson", "purl": "pkg:maven/jackson", "licenses": [{"license": {"id": "Apache-2.0"}}], "scope": "required"}]
	}`)
	source := []byte(`{"components": []}`)

	merged, err := Merge(image, source)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	var d struct {
		SerialNumber string `json:"serialNumber"`
		Metadata     struct {
			Tools map[string]string `json:"tools"`
		} `json:"metadata"`
		Components []map[string]any `json:"components"`
	}
	if err := json.Unmarshal(merged, &d); err != nil {
		t.Fatalf("merged output is not valid JSON: %v", err)
	}
	if d.SerialNumber != "urn:uuid:1234" {
		t.Errorf("serialNumber lost: %q", d.SerialNumber)
	}
	if d.Metadata.Tools["syft"] != "1.19.0" {
		t.Errorf("metadata.tools lost: %v", d.Metadata.Tools)
	}
	if len(d.Components) != 1 {
		t.Fatalf("components = %v", d.Components)
	}
	if _, ok := d.Components[0]["licenses"]; !ok {
		t.Errorf("component licenses lost: %v", d.Components[0])
	}
	if d.Components[0]["scope"] != "required" {
		t.Errorf("component scope lost: %v", d.Components[0])
	}
}

func TestMergeMissingComponents(t *testing.T) {
	// Neither document lists components: the output still carries an empty
	// components array, like the Python original's unconditional
	// assignment.
	merged, err := Merge([]byte(`{"bomFormat":"CycloneDX"}`), []byte(`{}`))
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if got := names(t, merged); len(got) != 0 {
		t.Errorf("merged components = %v, want none", got)
	}
	if !strings.Contains(string(merged), `"components": []`) {
		t.Errorf("output lacks an empty components array: %s", merged)
	}
}

func TestMergeInvalidInput(t *testing.T) {
	if _, err := Merge([]byte(`{`), doc()); err == nil {
		t.Error("expected an error for a malformed image SBOM")
	}
	if _, err := Merge(doc(), []byte(`not json`)); err == nil {
		t.Error("expected an error for a malformed source SBOM")
	}
	// "components" present but not an array must not silently drop the
	// image SBOM's content.
	if _, err := Merge([]byte(`{"components":"oops"}`), doc()); err == nil {
		t.Error(`expected an error when "components" is not an array`)
	}
}

func TestBlobURL(t *testing.T) {
	sbom := []byte("the merged sbom bytes")
	sum := sha256.Sum256(sbom)
	want := "quay.io/org/app@sha256:" + hex.EncodeToString(sum[:])
	if got := BlobURL("quay.io/org/app:1.0", sbom); got != want {
		t.Errorf("BlobURL = %q, want %q", got, want)
	}
	// A port in the reference survives; a tag does not.
	if got := BlobURL("quay.io:5000/org/app:1.0", sbom); got != "quay.io:5000/org/app@sha256:"+hex.EncodeToString(sum[:]) {
		t.Errorf("BlobURL with port = %q", got)
	}
}

func TestScanArgsPinCycloneDX16(t *testing.T) {
	got := Scan{Scheme: "dir", Path: "/src", Output: "sbom-source.json"}.Args()
	want := []string{"dir:/src", "--output", "cyclonedx-json@1.6=sbom-source.json"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("Scan.Args() = %v, want %v", got, want)
	}
	if OutputFormat != "cyclonedx-json@1.6" {
		t.Errorf("OutputFormat changed to %q; RHTPA accepts CycloneDX 1.6 or SPDX 2.3 only", OutputFormat)
	}
}

func TestScanValidate(t *testing.T) {
	cases := []Scan{
		{Scheme: "registry", Path: "/src", Output: "out.json"}, // not one of the two schemes
		{Scheme: "dir", Path: "", Output: "out.json"},          // no path
		{Scheme: "oci-dir", Path: "/img", Output: ""},          // no output
	}
	for _, s := range cases {
		if err := s.validate(); err == nil {
			t.Errorf("expected %v to be rejected", s)
		}
	}
	for _, s := range []Scan{
		{Scheme: "dir", Path: "/src", Output: "out.json"},
		{Scheme: "oci-dir", Path: "/img", Output: "out.json"},
	} {
		if err := s.validate(); err != nil {
			t.Errorf("expected %v to be accepted: %v", s, err)
		}
	}
}
