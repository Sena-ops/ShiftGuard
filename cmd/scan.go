package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Sena-ops/shiftguard/internal/parser"
	"github.com/Sena-ops/shiftguard/internal/scanner"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var recursive bool
var filterTypes string
var outputFormat string
var debugMode bool
var whichScanner string

var logger *zap.SugaredLogger

type ScanResult struct {
	Type  string   `json:"type"`
	Files []string `json:"files"`
}

// SARIF structs (resumidos)
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
		// Inicializa logger
		var logConfig zap.Config
		if debugMode {
			logConfig = zap.NewDevelopmentConfig()
		} else {
			logConfig = zap.NewProductionConfig()
			logConfig.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
		}
		logConfig.Encoding = "console"
		rawLogger, err := logConfig.Build()
		if err != nil {
			fmt.Println("Erro ao iniciar logger:", err)
			os.Exit(1)
		}
		defer rawLogger.Sync()
		logger = rawLogger.Sugar()

		path := args[0]
		logger.Infof("Escaneando diretório: %s (recursivo: %v)", path, recursive)

		files, err := parser.DetectIaCFiles(path, recursive)
		if err != nil {
			logger.Errorw("Erro ao escanear", "erro", err)
			os.Exit(1)
		}

		allowedTypes := map[string]bool{}
		if filterTypes != "" {
			for _, t := range splitAndTrim(filterTypes) {
				allowedTypes[t] = true
			}
			logger.Debugf("Tipos filtrados: %v", allowedTypes)
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
				logger.Errorw("Erro ao gerar JSON", "erro", err)
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
				logger.Errorw("Erro ao gerar SARIF", "erro", err)
				os.Exit(1)
			}
			fmt.Println(string(encoded))
			return
		}

		// Saída padrão terminal
		logger.Infof("✅ Resultado do Scan:")
		for iacType, paths := range iacResults {
			fmt.Printf("- %s: %d arquivo(s)\n", iacType, len(paths))
			for _, p := range paths {
				fmt.Printf("    • %s\n", p)
			}
		}

		// Execução Scaner
		if whichScanner != "" {
			logger.Infof("Executando scanner: %s...", whichScanner)

			err := os.MkdirAll(".shiftguard", 0755)
			if err != nil {
				logger.Errorw("Erro ao criar diretório .shiftguard", "erro", err)
				os.Exit(1)
			}

			output, outputPath, err := scanner.Execute(whichScanner, []string{path})
			if err != nil {
				logger.Errorw("Erro ao executar scanner", "erro", err)
			} else {
				err := os.WriteFile(outputPath, output, 0644)
				if err != nil {
					logger.Errorw("Erro ao salvar resultados", "erro", err)
				} else {
					logger.Infow("Resultado salvo com sucesso", "scanner", whichScanner, "arquivo", outputPath)
				}
			}
		}

	},
}

func init() {
	scanCmd.Flags().BoolVarP(&recursive, "recursive", "r", false, "Escaneia diretórios recursivamente")
	scanCmd.Flags().StringVarP(&filterTypes, "filter", "f", "", "Filtra os tipos IaC desejados (ex: terraform,kubernetes)")
	scanCmd.Flags().StringVarP(&outputFormat, "output", "o", "", "Formato da saída (json, markdown, sarif)")
	scanCmd.Flags().StringVarP(&whichScanner, "with", "w", "", "Executa scanner específico (ex: trivy, kics, semgrep)")
	scanCmd.Flags().BoolVar(&debugMode, "debug", false, "Habilita logs em nível debug")
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
