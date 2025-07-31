package parser

import (
	"os"
	"testing"
)

func writeTempFile(t *testing.T, content string) string {
	f, err := os.CreateTemp("", "*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString(content)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	return f.Name()
}

func TestIsKubernetesManifest(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected bool
	}{
		{"valid_manifest", "apiVersion: v1\nkind: Pod", true},
		{"no_apiversion", "kind: Deployment", false},
		{"empty_file", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTempFile(t, tt.content)
			defer os.Remove(path)

			result := IsKubernetesManifest(path)
			if result != tt.expected {
				t.Errorf("esperado %v, obtido %v", tt.expected, result)
			}
		})
	}
}
