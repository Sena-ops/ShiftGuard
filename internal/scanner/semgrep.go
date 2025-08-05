// internal/scanner/semgrep.go
package scanner

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func RunSemgrep(paths []string) ([]byte, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("nenhum caminho fornecido para o Semgrep")
	}

	outputPath := filepath.Join(".shiftguard", "semgrep-results.json")

	args := []string{
		"scan",
		"--config=auto", // regras default
		"--json",        // saída JSON
		"--output", outputPath,
	}
	args = append(args, paths...)

	cmd := exec.Command("semgrep", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("erro ao executar Semgrep: %w\nstderr: %s", err, string(out))
	}

	output, err := os.ReadFile(outputPath)
	if err != nil {
		return nil, fmt.Errorf("erro ao ler resultado do Semgrep: %w", err)
	}

	return output, nil
}
