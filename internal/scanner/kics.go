package scanner

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func RunKICS(paths []string) ([]byte, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("nenhum path informado para KICS")
	}

	absPath, err := filepath.Abs(paths[0])
	if err != nil {
		return nil, fmt.Errorf("erro ao resolver caminho absoluto: %v", err)
	}

	// Garante que a pasta .shiftguard existe
	_ = os.MkdirAll(".shiftguard", 0755)

	args := []string{
		"run", "--rm",
		"-v", fmt.Sprintf("%s:/scan", absPath),
		"-v", fmt.Sprintf("%s:/output", ".shiftguard"),
		"checkmarx/kics:latest",
		"scan", "-p", "/scan",
		"--report-formats", "json",
		"--output-path", "/output",
	}

	cmd := exec.Command("docker", args...)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("erro ao executar KICS via Docker: %v\nstderr: %s", err, stderr.String())
	}

	outputPath := ".shiftguard/results.json"
	output, err := os.ReadFile(outputPath)
	if err != nil {
		return nil, fmt.Errorf("erro ao ler resultado do KICS: %v", err)
	}

	return output, nil
}
