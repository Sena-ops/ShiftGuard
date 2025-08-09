package sarif

import (
	"encoding/json"
	"fmt"
)

type kicsReport struct {
	Queries []struct {
		QueryName string `json:"query_name"`
		QueryID   string `json:"query_id"`
		Severity  string `json:"severity"`
		Files     []struct {
			FileName string `json:"file_name"`
			Line     int    `json:"line"`
		} `json:"files"`
	} `json:"queries"`
}

func ConvertKicsToSarif(input []byte) (*Log, error) {
	var kics kicsReport
	if err := json.Unmarshal(input, &kics); err != nil {
		return nil, fmt.Errorf("erro ao fazer parse do JSON do KICS: %w", err)
	}

	var results []Result
	for _, query := range kics.Queries {
		for _, file := range query.Files {
			results = append(results, Result{
				RuleID: fmt.Sprintf("%s: %s", query.QueryID, query.QueryName),
				Level:  mapKicsSeverity(query.Severity),
				Message: Message{
					Text: query.QueryName,
				},
				Locations: []Location{
					{
						PhysicalLocation: PhysicalLocation{
							ArtifactLocation: ArtifactLocation{
								URI: file.FileName,
							},
							Region: Region{
								StartLine: file.Line,
							},
						},
					},
				},
			})
		}
	}

	return &Log{
		Version: "2.1.0",
		Schema:  "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
		Runs: []Run{
			{
				Tool: Tool{
					Driver: Driver{
						Name:    "KICS",
						Version: "1.0.0", // ou capturar dinamicamente
					},
				},
				Results: results,
			},
		},
	}, nil
}

func mapKicsSeverity(sev string) string {
	switch sev {
	case "HIGH", "CRITICAL":
		return "error"
	case "MEDIUM":
		return "warning"
	default:
		return "note"
	}
}
