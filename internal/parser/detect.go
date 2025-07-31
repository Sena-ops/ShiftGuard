package parser

import (
	"bufio"
	"os"
	"strings"
)

// IsKubernetesManifest analisa o conteúdo do arquivo YAML para verificar se é um manifesto Kubernetes.
func IsKubernetesManifest(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "apiVersion:") {
			return true
		}
	}

	return false
}
