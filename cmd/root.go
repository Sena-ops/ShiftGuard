package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "shiftguard",
	Short: "ShiftGuard - Scanner IaC & SBOM Assinado",
}

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}
