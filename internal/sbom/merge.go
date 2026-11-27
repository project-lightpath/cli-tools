// Package sbom generates and merges the CycloneDX SBOMs the detection
// pipeline consumes.
//
// Both halves are ports of steps from the demo's buildah-rhtap task
// (tssc-validated-pattern), which carried them as shell and Python scripts
// inside the task YAML. As Go code they are unit-testable and the task
// shrinks to a flag-mapping wrapper.
package sbom

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/project-lightpath/cli-tools/internal/imageref"
)

// component is the part of a CycloneDX component the merge needs to see.
// Everything else a component carries survives the merge untouched.
//
// Purl is a pointer so "no purl" (nil) stays distinct from `purl: ""`
// (present but empty): the original deduplicated on purl presence, and an
// empty purl is a value it would happily deduplicate on.
type component struct {
	Type string  `json:"type"`
	Name string  `json:"name"`
	Purl *string `json:"purl"`
}

// rawComponent pairs a component's bytes with its sort key, so the merged
// list can be ordered without re-marshalling anything.
type rawComponent struct {
	comp component
	raw  json.RawMessage
}

func (r rawComponent) sortKey() string { return r.comp.Type + r.comp.Name }

// Merge folds the source SBOM into the image SBOM and returns the merged
// document.
//
// Components are deduplicated by purl: a source component the image SBOM
// already lists is dropped, and so is a second source component with a purl
// already seen. Components without a purl are never deduplicated -- they are
// the operating-system packages only the image scan reports. The merged list
// is sorted by type then name, stably, matching the Python original.
//
// The image document is the base: every field it carries besides components
// (bomFormat, serialNumber, metadata, ...) passes through unchanged.
func Merge(image, source []byte) ([]byte, error) {
	imgDoc, err := decodeDocument(image, "image SBOM")
	if err != nil {
		return nil, err
	}
	srcDoc, err := decodeDocument(source, "source SBOM")
	if err != nil {
		return nil, err
	}

	merged, err := components(imgDoc, "image SBOM")
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, rc := range merged {
		if rc.comp.Purl != nil {
			seen[*rc.comp.Purl] = true
		}
	}
	srcComponents, err := components(srcDoc, "source SBOM")
	if err != nil {
		return nil, err
	}
	for _, rc := range srcComponents {
		if rc.comp.Purl != nil {
			if seen[*rc.comp.Purl] {
				continue
			}
			seen[*rc.comp.Purl] = true
		}
		merged = append(merged, rc)
	}
	sort.SliceStable(merged, func(i, j int) bool {
		return merged[i].sortKey() < merged[j].sortKey()
	})

	list := make([]json.RawMessage, len(merged))
	for i, rc := range merged {
		list[i] = rc.raw
	}
	rawList, err := json.Marshal(list)
	if err != nil {
		return nil, fmt.Errorf("re-encoding components: %w", err)
	}
	imgDoc["components"] = rawList

	// json.Marshal writes a RawMessage compacted onto one line, so the
	// document is marshalled compact first and re-indented in a second
	// pass. The output is pretty and byte-stable, like the Python
	// original's json.dump(indent=4). One difference survives: object keys
	// come out sorted rather than in insertion order, which no JSON
	// consumer this feeds cares about.
	compact, err := json.Marshal(imgDoc)
	if err != nil {
		return nil, fmt.Errorf("re-encoding merged SBOM: %w", err)
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, compact, "", "    "); err != nil {
		return nil, fmt.Errorf("re-indenting merged SBOM: %w", err)
	}
	return buf.Bytes(), nil
}

// BlobURL returns where the merged SBOM would live as a registry blob: the
// image reference with its tag replaced by the SBOM's own sha256 digest.
func BlobURL(image string, sbom []byte) string {
	sum := sha256.Sum256(sbom)
	return imageref.StripTag(image) + "@sha256:" + hex.EncodeToString(sum[:])
}

func decodeDocument(doc []byte, what string) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(doc, &m); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", what, err)
	}
	return m, nil
}

func components(doc map[string]json.RawMessage, what string) ([]rawComponent, error) {
	raw, ok := doc["components"]
	if !ok {
		return nil, nil
	}
	var list []json.RawMessage
	if err := json.Unmarshal(raw, &list); err != nil {
		// The document parsed as JSON but "components" is not an array.
		// Report it rather than silently dropping half the SBOM.
		return nil, fmt.Errorf("parsing %s components: %w", what, err)
	}
	out := make([]rawComponent, 0, len(list))
	for _, raw := range list {
		var c component
		if err := json.Unmarshal(raw, &c); err != nil {
			continue // a component that is not an object cannot match or sort
		}
		out = append(out, rawComponent{comp: c, raw: raw})
	}
	return out, nil
}
