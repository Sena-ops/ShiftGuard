package model

type Severity string

const (
	SevCritical Severity = "CRITICAL"
	SevHigh     Severity = "HIGH"
	SevMedium   Severity = "MEDIUM"
	SevLow      Severity = "LOW"
	SevInfo     Severity = "INFO"
)

type Finding struct {
	ToolName  string   // "kics" | "trivy" | "semgrep" | "shiftguard"
	RuleID    string   // id/regra do scanner
	RuleName  string   // nome da regra, se houver
	Severity  Severity // severidade normalizada
	Message   string   // descrição curta
	FilePath  string   // caminho relativo/normalizado
	StartLine int      // 1-based
	EndLine   int      // opcional (0 = sem fim)
	HelpURI   string   // link docs/regra (se disponível)
	CWE       []string // ex: ["CWE-79"]
}
