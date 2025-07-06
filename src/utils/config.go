package utils

import (
	"KidStoreBotBE/src/types"
	"log"
	"os"

	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
)

// Global constant-like variable (readonly in practice)
var EpicClient string
var EpicSecret string

func init() {
	//first check if the file exists and then load it
	if _, err := os.Stat(".env"); err == nil {
		if err := godotenv.Load(); err != nil {
			log.Fatalf("Error loading .env file: %v", err)
		}
	}
	// Process environment variables into Config struct
	var cfg types.EnvConfigType
	if err := envconfig.Process("", &cfg); err != nil {
		log.Fatalf("Error processing environment variables: %v", err)
	}

	// Set the global variable
	EpicClient = cfg.Epic_client
	EpicSecret = cfg.Epic_secret
}
