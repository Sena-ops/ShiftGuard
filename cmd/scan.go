package cmd

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Sena-ops/shiftguard/internal/adapters"
	"github.com/Sena-ops/shiftguard/internal/logging"
	"github.com/Sena-ops/shiftguard/internal/model"
	"github.com/Sena-ops/shiftguard/internal/parser"
	"github.com/Sena-ops/shiftguard/internal/scanner"
	sarif "github.com/Sena-ops/shiftguard/internal/sarif"
	"github.com/spf13/cobra"
)

var recursive bool
var filterTypes string
var outputFormat string
var debugMode bool
var whichScanner string

type ScanResult struct {
	Type  string   `json:"type"`
	Files []string `json:"files"`
}

var scanCmd = &cobra.Command{
	Use:   "scan [caminho]",
	Short: "Escaneia um diretório em busca de arquivos IaC",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		logging.InitLogger(debugMode)
		log := logging.Logger

		path := args[0]
		files, err := parser.DetectIaCFiles(path, recursive)
		if err != nil {
			log.Errorw("Erro ao escanear", "erro", err)
			os.Exit(1)
		}

		// Filtro por tipo, se fornecido
		allowed := map[string]bool{}
		if filterTypes != "" {
			for _, t := range splitAndTrim(filterTypes) {
				allowed[t] = true
			}
		}

		// Monta o mapa de resultados (tipo -> paths)
		iacResults := map[string][]string{}
		for _, f := range files {
			tp := string(f.Type)
			if len(allowed) > 0 && !allowed[tp] {
				continue
			}
			iacResults[tp] = append(iacResults[tp], f.Path)
		}

		// === LISTAGEM SEMPRE ===
		fmt.Println("✅ Resultado do Scan:")
		if len(iacResults) == 0 {
			fmt.Println("  (nenhum arquivo IaC detectado)")
		} else {
			for tp, paths := range iacResults {
				fmt.Printf("- %s: %d arquivo(s)\n", tp, len(paths))
				for _, p := range paths {
					fmt.Printf("    • %s\n", p)
				}
			}
		}
		fmt.Println()
		// =======================

		switch strings.ToLower(outputFormat) {
		case "json":
			var out []ScanResult
			for tp, paths := range iacResults {
				out = append(out, ScanResult{Type: tp, Files: paths})
			}
			b, err := json.MarshalIndent(out, "", "  ")
			if err != nil {
				log.Errorw("Erro ao gerar JSON", "erro", err)
				os.Exit(1)
			}
			fmt.Println(string(b))
			return

		case "markdown":
			var b strings.Builder
			b.WriteString("## 📋 Resultado do Scan IaC\n\n")
			for tp, paths := range iacResults {
				b.WriteString(fmt.Sprintf("### %s (%d arquivo(s))\n", tp, len(paths)))
				for _, p := range paths {
					b.WriteString(fmt.Sprintf("- %s\n", p))
				}
				b.WriteString("\n")
			}
			fmt.Println(b.String())
			return

		case "sarif":
			var findings []model.Finding
			fileBase := "shiftguard"
			toolName := "ShiftGuard"

			if whichScanner != "" {
				scn := strings.ToLower(whichScanner)
				fileBase = scn
				toolName = strings.ToUpper(scn)

				out, _, err := scanner.Execute(scn, []string{path})
				if err != nil && len(out) == 0 {
					// Alguns scanners (ex.: KICS) podem não escrever no stdout
					log.Warnw("Scanner retornou erro ou stdout vazio; tentando arquivo de resultados", "scanner", scn, "erro", err)
				}

				// 1) Tenta parsear o stdout
				switch scn {
				case "kics":
					if len(out) > 0 {
						if parsed, e := adapters.ParseKICSBytes(out); e == nil {
							findings = parsed
						}
					}
				case "trivy":
					if len(out) > 0 {
						if parsed, e := adapters.ParseTrivyBytes(out); e == nil {
							findings = parsed
						}
					}
				case "semgrep":
					if len(out) > 0 {
						if parsed, e := adapters.ParseSemgrepBytes(out); e == nil {
							findings = parsed
						}
					}
				default:
					log.Warnw("Scanner não suportado", "scanner", scn)
				}

				// 2) Fallback: procurar JSON salvo em pastas conhecidas
				if len(findings) == 0 {
					if p := findFirstJSONMulti(
						filepath.Join(".shiftguard", "results"),
						filepath.Join(".shiftguard", "kics-results"),
						filepath.Join(".shiftguard", "trivy-results"),
						filepath.Join(".shiftguard", "semgrep-results"),
						".shiftguard",
					); p != "" {
						log.Infow("Usando JSON de arquivo (fallback)", "path", p)
						switch scn {
						case "kics":
							if parsed, e := adapters.ParseKICSFile(p); e == nil {
								findings = parsed
							}
						case "trivy":
							if parsed, e := adapters.ParseTrivyFile(p); e == nil {
								findings = parsed
							}
						case "semgrep":
							if parsed, e := adapters.ParseSemgrepFile(p); e == nil {
								findings = parsed
							}
						}
					}
				}

				// 3) Fallback específico do KICS: detectar por conteúdo
				if len(findings) == 0 && scn == "kics" {
					if p := findKICSJSONByContent(".shiftguard"); p != "" {
						log.Infow("Detectado JSON do KICS pelo conteúdo", "path", p)
						if parsed, e := adapters.ParseKICSFile(p); e == nil {
							findings = parsed
						} else {
							log.Warnw("Falha ao parsear JSON KICS", "erro", e)
						}
					}
				}
			}

			// 4) Fallback total: se ainda não há findings, cria um por arquivo detectado
			if len(findings) == 0 {
				for tp, paths := range iacResults {
					for _, p := range paths {
						findings = append(findings, model.Finding{
							ToolName:  "shiftguard",
							RuleID:    tp,
							RuleName:  tp,
							Severity:  model.SevInfo,
							Message:   "Arquivo detectado",
							FilePath:  p,
							StartLine: 1,
						})
					}
				}
			}

			// Exporta SARIF
			_ = os.MkdirAll(".shiftguard", 0o755)
			sarif.SortFindings(findings)
			outPath, err := sarif.Export(findings, ".shiftguard", fileBase, toolName, "0.1.0")
			if err != nil {
				log.Errorw("Erro ao exportar SARIF", "erro", err)
				os.Exit(1)
			}
			fmt.Println("📦 SARIF salvo em:", outPath)
			return
		}

		// Execução opcional do scanner quando não é -o (apenas para salvar saída bruta)
		if whichScanner != "" && strings.ToLower(outputFormat) == "" {
			log.Infof("Executando scanner: %s...", whichScanner)
			out, outPath, err := scanner.Execute(whichScanner, []string{path})
			if err != nil {
				log.Errorw("Erro ao executar scanner", "erro", err)
			} else if err := os.WriteFile(outPath, out, 0o644); err != nil {
				log.Errorw("Erro ao salvar resultados", "erro", err)
			} else {
				log.Infow("Resultado salvo com sucesso", "scanner", whichScanner, "arquivo", outPath)
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
	var out []string
	for _, p := range strings.Split(s, ",") {
		if t := strings.TrimSpace(strings.ToLower(p)); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// ---------- Helpers de fallback de resultados (.json) ----------

func findFirstJSONMulti(dirs ...string) string {
	for _, d := range dirs {
		if p := findFirstJSON(d); p != "" {
			return p
		}
	}
	return ""
}

func findFirstJSON(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	var best string
	var bestMod time.Time
	for _, e := range entries {
		if e.IsDir() {
			if p := findFirstJSON(filepath.Join(dir, e.Name())); p != "" {
				if info, _ := os.Stat(p); info != nil && info.ModTime().After(bestMod) {
					bestMod = info.ModTime()
					best = p
				}
			}
			continue
		}
		if !strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
			continue
		}
		p := filepath.Join(dir, e.Name())
		if info, err := os.Stat(p); err == nil && info.ModTime().After(bestMod) {
			bestMod = info.ModTime()
			best = p
		}
	}
	return best
}

// Varre .shiftguard e detecta JSON do KICS pelo conteúdo (kics_version/queries)
func findKICSJSONByContent(root string) string {
	var best string
	var bestMod time.Time

	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
			return nil
		}
		b, e := os.ReadFile(p)
		if e != nil || len(b) == 0 {
			return nil
		}
		if isKICSJSON(b) {
			if info, e := os.Stat(p); e == nil && info.ModTime().After(bestMod) {
				bestMod = info.ModTime()
				best = p
			}
		}
		return nil
	})
	return best
}

func isKICSJSON(b []byte) bool {
	// heurística leve
	s := strings.ToLower(string(b))
	if strings.Contains(s, "\"kics_version\"") {
		return true
	}
	// presença de queries/Queries
	type probe struct {
		Queries any `json:"queries"`
	}
	var p probe
	if json.Unmarshal(b, &p) == nil && p.Queries != nil {
		return true
	}
	type probeUp struct {
		Queries any `json:"Queries"`
	}
	var u probeUp
	return json.Unmarshal(b, &u) == nil && u.Queries != nil
}
