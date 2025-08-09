package adapters

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/Sena-ops/shiftguard/internal/model"
)

// Estrutura EXATA do JSON do KICS que você me enviou (campos lowercase)
type kicsJSON struct {
	Queries []struct {
		QueryName   string `json:"query_name"`
		QueryID     string `json:"query_id"`
		QueryURL    string `json:"query_url"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
		CWE         string `json:"cwe"`
		Files       []struct {
			FileName string `json:"file_name"`
			Line     int    `json:"line"`
		} `json:"files"`
	} `json:"queries"`
}

// Algumas builds antigas exportavam "Queries" com maiúsculo; deixo um fallback leve.
type kicsJSONUpper struct {
	Queries []struct {
		QueryName   string `json:"query_name"`
		QueryID     string `json:"query_id"`
		QueryURL    string `json:"query_url"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
		CWE         string `json:"cwe"`
		Files       []struct {
			FileName string `json:"file_name"`
			Line     int    `json:"line"`
		} `json:"files"`
	} `json:"Queries"`
}

func ParseKICSBytes(b []byte) ([]model.Finding, error) {
	var doc kicsJSON
	err := json.Unmarshal(b, &doc)
	if err != nil || len(doc.Queries) == 0 {
		// fallback para "Queries" (maiúsculo)
		var up kicsJSONUpper
		if e2 := json.Unmarshal(b, &up); e2 == nil && len(up.Queries) > 0 {
			// Reaproveita a mesma estrutura
			doc.Queries = up.Queries
		}
	}

	out := make([]model.Finding, 0, 32)
	for _, q := range doc.Queries {
		msg := strings.TrimSpace(q.Description)
		if msg == "" {
			msg = q.QueryName
		}
		for _, f := range q.Files {
			// Normaliza caminhos vindos do container (../../scan/..., ../, ./, scan/)
			fp := filepath.ToSlash(f.FileName)
			for strings.HasPrefix(fp, "../") {
				fp = strings.TrimPrefix(fp, "../")
			}
			fp = strings.TrimPrefix(fp, "./")
			fp = strings.TrimPrefix(fp, "scan/")
			fp = strings.TrimPrefix(fp, "/scan/")

			var cwe []string
			if strings.TrimSpace(q.CWE) != "" {
				cwe = []string{q.CWE}
			}

			out = append(out, model.Finding{
				ToolName:  "kics",
				RuleID:    q.QueryID,
				RuleName:  q.QueryName,
				Severity:  kicsSeverity(q.Severity),
				Message:   msg,
				FilePath:  fp,
				StartLine: safeLine(f.Line), // <- vem do adapters/common.go
				HelpURI:   q.QueryURL,
				CWE:       cwe,
			})
		}
	}
	return out, nil
}

func ParseKICSFile(path string) ([]model.Finding, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseKICSBytes(b)
}

func kicsSeverity(s string) model.Severity {
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
