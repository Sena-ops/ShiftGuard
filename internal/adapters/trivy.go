package adapters

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/Sena-ops/shiftguard/internal/model"
)

// Compatível com seu trivy-results.json (misconfig)
type trivyJSON struct {
	Results []struct {
		Target            string `json:"Target"`
		Misconfigurations []struct {
			ID            string   `json:"ID"`
			Title         string   `json:"Title"`
			Description   string   `json:"Description"`
			Severity      string   `json:"Severity"`
			PrimaryURL    string   `json:"PrimaryURL"`
			References    []string `json:"References"`
			CauseMetadata struct {
				StartLine int `json:"StartLine"`
				EndLine   int `json:"EndLine"`
			} `json:"CauseMetadata"`
		} `json:"Misconfigurations"`
	} `json:"Results"`
}

func ParseTrivyBytes(b []byte) ([]model.Finding, error) {
	var doc trivyJSON
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}

	var out []model.Finding
	for _, r := range doc.Results {
		target := filepath.ToSlash(r.Target)
		for _, m := range r.Misconfigurations {
			help := m.PrimaryURL
			if help == "" && len(m.References) > 0 {
				help = m.References[0]
			}
			out = append(out, model.Finding{
				ToolName:  "trivy",
				RuleID:    m.ID,
				RuleName:  m.Title,
				Severity:  trivySeverity(m.Severity),
				Message:   firstNonEmpty(m.Description, m.Title),
				FilePath:  target,
				StartLine: safeLine(m.CauseMetadata.StartLine),
				EndLine:   safeLine(m.CauseMetadata.EndLine),
				HelpURI:   help,
			})
		}
	}
	return out, nil
}

func ParseTrivyFile(path string) ([]model.Finding, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseTrivyBytes(b)
}

func trivySeverity(s string) model.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return model.SevCritical
	case "HIGH":
		return model.SevHigh
	case "MEDIUM":
		return model.SevMedium
	case "LOW":
		return model.SevLow
	default:
		return model.SevInfo
	}
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
