package imageref

import "testing"

func TestStripTag(t *testing.T) {
	cases := []struct {
		image string
		want  string
	}{
		{"quay.io/org/app:1.0", "quay.io/org/app"},
		{"quay.io/org/app", "quay.io/org/app"},
		// The port survives: ":5000" is not at the end of the string.
		{"quay.io:5000/org/app:latest", "quay.io:5000/org/app"},
		{"quay.io:5000/org/app", "quay.io:5000/org/app"},
		// A port-only reference has no tag to strip, and "5000" alone at
		// the end is grammatically a tag -- the documented quirk this
		// shares with the shell and Python originals.
		{"localhost:5000", "localhost"},
		{"quay.io/org/app:v1.2.3-rhel_01", "quay.io/org/app"},
		{"quay.io/org/app:run-abc123", "quay.io/org/app"},
	}
	for _, c := range cases {
		if got := StripTag(c.image); got != c.want {
			t.Errorf("StripTag(%q) = %q, want %q", c.image, got, c.want)
		}
	}
}
