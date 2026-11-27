// Package imageref holds the image-reference syntax the sbom and imagebuild
// tools share: stripping a trailing tag without eating a registry port.
package imageref

import "regexp"

// tagSuffix matches a ":tag" at the very end of a reference, using the OCI
// distribution spec's tag grammar.
// https://github.com/opencontainers/distribution-spec/blob/main/spec.md
//
// Requiring the match to end the string is what keeps a registry port
// intact: in "quay.io:5000/ns/app:1.0" only ":1.0" can match, because
// ":5000" is followed by the rest of the reference. A bare "host:5000" with
// no path is indistinguishable from "host" with tag "5000" and loses the
// port; the reference never appears in that form, and the shell and Python
// versions this package ports had the same behavior.
var tagSuffix = regexp.MustCompile(`:[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}$`)

// StripTag returns image with a trailing ":tag" removed, or image unchanged
// when it carries no tag. The repository (including any host:port) survives.
func StripTag(image string) string {
	return tagSuffix.ReplaceAllString(image, "")
}
