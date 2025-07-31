package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Sena-ops/shiftguard/internal/parser"
	"github.com/spf13/cobra"
)

var recursive bool
var filterTypes string
var outputFormat string

type ScanResult struct {
	Type  string   `json:"type"`
	Files []string `json:"files"`
}

// SARIF v2.1.0 structures (mínimo necessário)
type SarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SarifRun `json:"runs"`
}

type SarifRun struct {
	Tool    SarifTool     `json:"tool"`
	Results []SarifResult `json:"results"`
}

type SarifTool struct {
	Driver SarifDriver `json:"driver"`
}

type SarifDriver struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type SarifResult struct {
	RuleID    string          `json:"ruleId"`
	Message   SarifMessage    `json:"message"`
	Locations []SarifLocation `json:"locations"`
}

type SarifMessage struct {
	Text string `json:"text"`
}

type SarifLocation struct {
	PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"`
}

type SarifPhysicalLocation struct {
	ArtifactLocation SarifArtifactLocation `json:"artifactLocation"`
	Region           SarifRegion           `json:"region"`
}

type SarifArtifactLocation struct {
	URI string `json:"uri"`
}

type SarifRegion struct {
	StartLine int `json:"startLine"`
}

var scanCmd = &cobra.Command{
	Use:   "scan [caminho]",
	Short: "Escaneia um diretório em busca de arquivos IaC",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		path := args[0]
		fmt.Printf("🔍 Escaneando diretório: %s (recursivo: %v)\n\n", path, recursive)

		files, err := parser.DetectIaCFiles(path, recursive)
		if err != nil {
			fmt.Println("Erro ao escanear:", err)
			os.Exit(1)
		}

		allowedTypes := map[string]bool{}
		if filterTypes != "" {
			for _, t := range splitAndTrim(filterTypes) {
				allowedTypes[t] = true
			}
		}

		iacResults := map[string][]string{}
		for _, f := range files {
			iacType := string(f.Type)
			if len(allowedTypes) > 0 && !allowedTypes[iacType] {
				continue
			}
			iacResults[iacType] = append(iacResults[iacType], f.Path)
		}

		switch strings.ToLower(outputFormat) {
		case "json":
			var jsonResults []ScanResult
			for iacType, paths := range iacResults {
				jsonResults = append(jsonResults, ScanResult{
					Type:  iacType,
					Files: paths,
				})
			}
			encoded, err := json.MarshalIndent(jsonResults, "", "  ")
			if err != nil {
				fmt.Println("Erro ao gerar JSON:", err)
				os.Exit(1)
			}
			fmt.Println(string(encoded))
			return

		case "markdown":
			var builder strings.Builder
			builder.WriteString("## 📋 Resultado do Scan IaC\n\n")
			for iacType, paths := range iacResults {
				builder.WriteString(fmt.Sprintf("### %s (%d arquivo(s))\n", iacType, len(paths)))
				for _, p := range paths {
					builder.WriteString(fmt.Sprintf("- %s\n", p))
				}
				builder.WriteString("\n")
			}
			fmt.Println(builder.String())
			return

		case "sarif":
			var results []SarifResult
			for iacType, paths := range iacResults {
				for _, p := range paths {
					results = append(results, SarifResult{
						RuleID: iacType,
						Message: SarifMessage{
							Text: fmt.Sprintf("Arquivo %s detectado", iacType),
						},
						Locations: []SarifLocation{
							{
								PhysicalLocation: SarifPhysicalLocation{
									ArtifactLocation: SarifArtifactLocation{
										URI: p,
									},
									Region: SarifRegion{
										StartLine: 1,
									},
								},
							},
						},
					})
				}
			}

			sarif := SarifLog{
				Version: "2.1.0",
				Schema:  "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
				Runs: []SarifRun{
					{
						Tool: SarifTool{
							Driver: SarifDriver{
								Name:    "ShiftGuard",
								Version: "0.1.0",
							},
						},
						Results: results,
					},
				},
			}

			encoded, err := json.MarshalIndent(sarif, "", "  ")
			if err != nil {
				fmt.Println("Erro ao gerar SARIF:", err)
				os.Exit(1)
			}
			fmt.Println(string(encoded))
			return

		default:
			fmt.Println("✅ Resultado do Scan:")
			for iacType, paths := range iacResults {
				fmt.Printf("- %s: %d arquivo(s)\n", iacType, len(paths))
				for _, p := range paths {
					fmt.Printf("    • %s\n", p)
				}
			}
		}
	},
}

func init() {
	scanCmd.Flags().BoolVarP(&recursive, "recursive", "r", false, "Escaneia diretórios recursivamente")
	scanCmd.Flags().StringVarP(&filterTypes, "filter", "f", "", "Filtra os tipos IaC desejados (ex: terraform,kubernetes)")
	scanCmd.Flags().StringVarP(&outputFormat, "output", "o", "", "Formato da saída (json, markdown, sarif)")
	rootCmd.AddCommand(scanCmd)
}

func splitAndTrim(s string) []string {
	var result []string
	for _, part := range strings.Split(s, ",") {
		trimmed := strings.TrimSpace(strings.ToLower(part))
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
