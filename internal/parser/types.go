package parser

type IaCType string

const (
	Terraform  IaCType = "terraform"
	Kubernetes IaCType = "kubernetes"
	Dockerfile IaCType = "dockerfile"
	ARM        IaCType = "arm"
	Bicep      IaCType = "bicep"
)

type IaCFile struct {
	Type IaCType
	Path string
}
