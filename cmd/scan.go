package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/Sena-ops/shiftguard/internal/parser"
	"github.com/spf13/cobra"
)

var recursive bool
var onlyTypes string

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

		// Filtrar tipos permitidos, se --only for usado
		allowedTypes := map[string]bool{}
		if onlyTypes != "" {
			for _, t := range splitAndTrim(onlyTypes) {
				allowedTypes[t] = true
			}
		}

		// Agrupar arquivos por tipo
		iacResults := map[string][]string{}
		for _, f := range files {
			iacType := string(f.Type)

			if len(allowedTypes) > 0 && !allowedTypes[iacType] {
				continue
			}

			iacResults[iacType] = append(iacResults[iacType], f.Path)
		}

		fmt.Println("✅ Resultado do Scan:")
		for iacType, paths := range iacResults {
			fmt.Printf("- %s: %d arquivo(s)\n", iacType, len(paths))
			for _, p := range paths {
				fmt.Printf("    • %s\n", p)
			}
		}
	},
}

func init() {
	scanCmd.Flags().BoolVarP(&recursive, "recursive", "r", false, "Escaneia diretórios recursivamente")
	scanCmd.Flags().StringVarP(&onlyTypes, "only", "o", "", "Filtra os tipos IaC desejados (ex: terraform,kubernetes)")
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
