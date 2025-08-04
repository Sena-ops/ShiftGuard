package logging

import (
	"go.uber.org/zap"
)

var Logger *zap.SugaredLogger

func InitLogger(debug bool) {
	var cfg zap.Config
	if debug {
		cfg = zap.NewDevelopmentConfig()
	} else {
		cfg = zap.NewProductionConfig()
		cfg.Level = zap.NewAtomicLevelAt(zap.WarnLevel)
	}
	cfg.Encoding = "console"
	logger, err := cfg.Build()
	if err != nil {
		panic("erro ao inicializar logger: " + err.Error())
	}
	Logger = logger.Sugar()
}
