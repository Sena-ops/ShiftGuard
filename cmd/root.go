package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "shiftguard",
	Short: "ShiftGuard é uma CLI para escanear arquivos IaC com foco em segurança.",
	Long:  `O ShiftGuard detecta e classifica arquivos IaC, gera SBOMs assinadas e integra scanners como Trivy, KICS e Semgrep.`,
}

// Execute inicia a CLI
func Execute() {
	rootCmd.AddCommand(scanCmd)
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
