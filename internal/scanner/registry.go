package scanner

import (
	"fmt"
)

type ScannerFunc func(paths []string) ([]byte, error)

var scanners = map[string]ScannerFunc{
	"trivy": func(paths []string) ([]byte, error) {
		if len(paths) == 0 {
			return nil, fmt.Errorf("nenhum path informado para trivy")
		}
		return RunTrivy(paths[0])
	},
	"kics":    RunKICS,
	"semgrep": RunSemgrep,
}

func Execute(scannerName string, paths []string) ([]byte, string, error) {
	fn, ok := scanners[scannerName]
	if !ok {
		return nil, "", fmt.Errorf("scanner '%s' não suportado", scannerName)
	}

	output, err := fn(paths)
	if err != nil {
		return nil, "", err
	}

	outputPath := fmt.Sprintf(".shiftguard/%s-results.json", scannerName)
	return output, outputPath, nil
}
