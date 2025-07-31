package cmd

import (
	"fmt"
	"os"

	"github.com/Sena-ops/shiftguard/internal/parser"
	"github.com/spf13/cobra"
)

var recursive bool

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

		// Agrupar arquivos por tipo
		iacResults := map[string][]string{}
		for _, f := range files {
			iacResults[string(f.Type)] = append(iacResults[string(f.Type)], f.Path)
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
	rootCmd.AddCommand(scanCmd)
}
