package cmd

import (
	"fmt"
	"github.com/Sena-ops/shiftguard/internal/parser"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
	"strings"
)

var scanCmd = &cobra.Command{
	Use:   "scan [caminho]",
	Short: "Escaneia um diretório em busca de arquivos IaC",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		path := args[0]
		fmt.Printf("🔍 Escaneando diretório: %s\n\n", path)

		// Mapear tipos
		type IaCResults map[string][]string

		iacResults := IaCResults{
			"terraform":  {},
			"kubernetes": {},
			"dockerfile": {},
			"arm":        {},
			"bicep":      {},
		}

		err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			name := strings.ToLower(info.Name())

			switch {
			case strings.HasSuffix(name, ".tf"):
				iacResults["terraform"] = append(iacResults["terraform"], path)
			case name == "dockerfile":
				iacResults["dockerfile"] = append(iacResults["dockerfile"], path)
			case strings.HasSuffix(name, ".bicep"):
				iacResults["bicep"] = append(iacResults["bicep"], path)
			case strings.HasSuffix(name, ".json"):
				iacResults["arm"] = append(iacResults["arm"], path)
			case strings.HasSuffix(name, ".yaml"), strings.HasSuffix(name, ".yml"):
				if parser.IsKubernetesManifest(path) {
					iacResults["kubernetes"] = append(iacResults["kubernetes"], path)
				}
			}

			return nil
		})

		if err != nil {
			fmt.Println("Erro ao escanear:", err)
			os.Exit(1)
		}

		fmt.Println("✅ Resultado do Scan:")
		for iacType, files := range iacResults {
			if len(files) == 0 {
				continue
			}
			fmt.Printf("- %s: %d arquivo(s)\n", iacType, len(files))
			for _, f := range files {
				fmt.Printf("    • %s\n", f)
			}
		}

	},
}
