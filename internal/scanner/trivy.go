package scanner

import (
	"bytes"
	"fmt"
	"os/exec"
)

// RunTrivy executa `trivy config` no diretório indicado
// e retorna a saída JSON bruta como []byte
func RunTrivy(targetPath string) ([]byte, error) {
	// Comando: trivy config -f json -q <path>
	cmd := exec.Command("trivy", "config", "-f", "json", "-q", targetPath)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("erro ao executar Trivy: %v\nstderr: %s", err, stderr.String())
	}

	return stdout.Bytes(), nil
}
