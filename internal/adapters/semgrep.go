package adapters

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/Sena-ops/shiftguard/internal/model"
)

type semgrepJSON struct {
	Results []struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct {
			Line int `json:"line"`
		} `json:"start"`
		End struct {
			Line int `json:"line"`
		} `json:"end"`
		Extra struct {
			Message  string `json:"message"`
			Severity string `json:"severity"` // INFO|WARNING|ERROR
			Metadata struct {
				Cwe  interface{} `json:"cwe"`  // string | []string | null
				Refs []string    `json:"refs"` // links
			} `json:"metadata"`
		} `json:"extra"`
	} `json:"results"`
}

func ParseSemgrepBytes(b []byte) ([]model.Finding, error) {
	var doc semgrepJSON
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}

	out := make([]model.Finding, 0, len(doc.Results))
	for _, r := range doc.Results {
		help := ""
		if len(r.Extra.Metadata.Refs) > 0 {
			help = r.Extra.Metadata.Refs[0]
		}
		out = append(out, model.Finding{
			ToolName:  "semgrep",
			RuleID:    r.CheckID,
			RuleName:  r.CheckID,
			Severity:  semgrepSeverity(r.Extra.Severity),
			Message:   r.Extra.Message,
			FilePath:  filepath.ToSlash(r.Path),
			StartLine: safeLine(r.Start.Line),
			EndLine:   safeLine(r.End.Line),
			HelpURI:   help,
			CWE:       toCwe(r.Extra.Metadata.Cwe),
		})
	}
	return out, nil
}

func ParseSemgrepFile(path string) ([]model.Finding, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseSemgrepBytes(b)
}

func semgrepSeverity(s string) model.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "ERROR":
		return model.SevHigh
	case "WARNING":
		return model.SevMedium
	default:
		return model.SevInfo
	}
}

func toCwe(v interface{}) []string {
	switch t := v.(type) {
	case string:
		if t != "" {
			return []string{t}
		}
	case []interface{}:
		out := []string{}
		for _, e := range t {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
