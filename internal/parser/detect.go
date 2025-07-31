package parser

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// IsKubernetesManifest analisa o conteúdo do YAML para detectar se é um manifest do K8s.
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

// DetectIaCFiles percorre o diretório informado e retorna uma lista de arquivos IaC classificados.
func DetectIaCFiles(rootPath string, recursive bool) ([]IaCFile, error) {
	var files []IaCFile

	err := filepath.WalkDir(rootPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() && path != rootPath && !recursive {
			return filepath.SkipDir
		}

		name := strings.ToLower(d.Name())

		switch {
		case strings.HasSuffix(name, ".tf"):
			files = append(files, IaCFile{Type: Terraform, Path: path})
		case name == "dockerfile":
			files = append(files, IaCFile{Type: Dockerfile, Path: path})
		case strings.HasSuffix(name, ".bicep"):
			files = append(files, IaCFile{Type: Bicep, Path: path})
		case strings.HasSuffix(name, ".json"):
			files = append(files, IaCFile{Type: ARM, Path: path})
		case strings.HasSuffix(name, ".yaml"), strings.HasSuffix(name, ".yml"):
			if IsKubernetesManifest(path) {
				files = append(files, IaCFile{Type: Kubernetes, Path: path})
			}
		}

		return nil
	})

	return files, err
}
