package config

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/IllumiKnowLabs/labstore/backend/internal/helper"
	"github.com/IllumiKnowLabs/labstore/backend/internal/security"
	"github.com/IllumiKnowLabs/labstore/backend/pkg/constants"
	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
)

const dotenvPath = ".env"

var Env ServerConfig

type ServerConfig struct {
	Host           string `env:"LS_HOST" envDefault:"localhost"`
	Port           uint16 `env:"LS_PORT" envDefault:"6789"`
	StorageRoot    string `env:"LS_STORAGE_ROOT" envDefault:"../data"`
	AdminAccessKey string `env:"LS_ADMIN_ACCESS_KEY" envDefault:"default"`
	AdminSecretKey string `env:"LS_ADMIN_SECRET_KEY" envDefault:"default_pass"`
}

func Load() {
	loadEnv()
}

func loadEnv() {
	if err := godotenv.Load(dotenvPath); err != nil {
		slog.Debug("No .env file found, skipping...")
	} else {
		slog.Debug("Loaded .env file", "path", dotenvPath)
	}

	Env = helper.Must(env.ParseAs[ServerConfig]())

	t := reflect.TypeOf(Env)
	v := reflect.ValueOf(Env)

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		value := v.Field(i)

		env_var_name := field.Tag.Get("env")
		env_var_value := fmt.Sprintf("%v", value)

		if strings.Contains(env_var_name, "SECRET") {
			if len(env_var_value) > 0 {
				env_var_value = security.Redacted
			} else {
				env_var_value = constants.Empty
			}
		}

		slog.Debug("Env var set", "name", env_var_name, "value", env_var_value)
	}

	cwd := helper.Must(os.Getwd())
	absStoragePath := helper.Must(filepath.Abs(Env.StorageRoot))
	relStoragePath := helper.Must(filepath.Rel(cwd, absStoragePath))

	slog.Debug(
		"Storage path resolved",
		"from", Env.StorageRoot,
		"to", relStoragePath,
		"relative_to", helper.TildePath(cwd),
	)

	Env.StorageRoot = relStoragePath
}
