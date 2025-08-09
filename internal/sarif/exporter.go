package sarif

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Sena-ops/shiftguard/internal/model"
)

type Log struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []Run  `json:"runs"`
}

type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type Driver struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Result struct {
	RuleID    string     `json:"ruleId"`
	Message   Message    `json:"message"`
	Level     string     `json:"level"` // error, warning, note
	Locations []Location `json:"locations"`
}

type Message struct {
	Text string `json:"text"`
}

type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           Region           `json:"region"`
}

type ArtifactLocation struct {
	URI string `json:"uri"`
}

type Region struct {
	StartLine int `json:"startLine"`
}

// Export recebe findings "comuns" e gera um arquivo .sarif 2.1.0
func Export(findings []model.Finding, outDir, fileBase, toolName, toolVersion string) (string, error) {
	results := make([]Result, 0, len(findings))
	for _, f := range findings {
		level := sevToLevel(f.Severity)
		fileURI := toURI(f.FilePath)
		if strings.TrimSpace(fileURI) == "" {
			fileURI = "UNKNOWN"
		}
		start := f.StartLine
		if start <= 0 {
			start = 1
		}

		results = append(results, Result{
			RuleID: f.RuleID,
			Level:  level,
			Message: Message{
				Text: strings.TrimSpace(f.Message),
			},
			Locations: []Location{
				{
					PhysicalLocation: PhysicalLocation{
						ArtifactLocation: ArtifactLocation{
							URI: fileURI,
						},
						Region: Region{
							StartLine: start,
						},
					},
				},
			},
		})
	}

	log := Log{
		Version: "2.1.0",
		// schema RTM reconhecido por GitHub/VSCode
		Schema: "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
		Runs: []Run{
			{
				Tool: Tool{
					Driver: Driver{
						Name:    toolName,
						Version: toolVersion,
					},
				},
				Results: results,
			},
		},
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", fmt.Errorf("criar dir sarif: %w", err)
	}
	outPath := filepath.Join(outDir, fileBase+".sarif")

	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal sarif: %w", err)
	}
	if err := os.WriteFile(outPath, data, 0o644); err != nil {
		return "", fmt.Errorf("escrever sarif: %w", err)
	}
	return outPath, nil
}

func SortFindings(fs []model.Finding) {
	sort.Slice(fs, func(i, j int) bool {
		if fs[i].FilePath == fs[j].FilePath {
			if fs[i].StartLine == fs[j].StartLine {
				return fs[i].RuleID < fs[j].RuleID
			}
			return fs[i].StartLine < fs[j].StartLine
		}
		return fs[i].FilePath < fs[j].FilePath
	})
}

func sevToLevel(s model.Severity) string {
	switch s {
	case model.SevCritical, model.SevHigh:
		return "error"
	case model.SevMedium:
		return "warning"
	default:
		return "note"
	}
}

func toURI(p string) string {
	p = strings.TrimSpace(p)
	p = filepath.ToSlash(p)
	for strings.HasPrefix(p, "../") {
		p = strings.TrimPrefix(p, "../")
	}
	return strings.TrimPrefix(p, "./")
}
