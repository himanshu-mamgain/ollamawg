package ollamawg

import (
	"encoding/json"
	"os"
	"testing"
)

// The npm package version decides what the publish workflow releases, and the
// binary reports Version, so the two must not drift apart.
func TestVersionMatchesNpmPackage(t *testing.T) {
	data, err := os.ReadFile("npm/ollamawg/package.json")
	if err != nil {
		t.Fatal(err)
	}
	var pkg struct {
		Version              string            `json:"version"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		t.Fatal(err)
	}
	if pkg.Version != Version {
		t.Errorf("npm/ollamawg/package.json version is %q, server.go Version is %q", pkg.Version, Version)
	}
	for name, v := range pkg.OptionalDependencies {
		if v != pkg.Version {
			t.Errorf("optionalDependencies[%q] is %q, want %q", name, v, pkg.Version)
		}
	}
}
