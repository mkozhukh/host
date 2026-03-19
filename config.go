package main

import (
	"log"
	"os"
	"strings"

	"github.com/knadh/koanf/parsers/toml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

type ServerConfig struct {
	Addr          string `koanf:"addr"`
	StaticDir     string `koanf:"static_dir"`
	SessionSecret string `koanf:"session_secret"`
}

type OAuthConfig struct {
	Provider     string   `koanf:"provider"`
	ClientID     string   `koanf:"client_id"`
	ClientSecret string   `koanf:"client_secret"`
	RedirectURL  string   `koanf:"redirect_url"`
	Scopes       []string `koanf:"scopes"`
}

type AuthConfig struct {
	Mode           string   `koanf:"mode"`
	AllowedEmails  []string `koanf:"allowed_emails"`
	AllowedDomains []string `koanf:"allowed_domains"`
}

type Config struct {
	Server ServerConfig `koanf:"server"`
	OAuth  OAuthConfig  `koanf:"oauth"`
	Auth   AuthConfig   `koanf:"auth"`
}

func LoadConfig(path string) (*Config, error) {
	k := koanf.New(".")

	// TOML file is optional (e.g. in Docker, config comes from env only)
	if _, err := os.Stat(path); err == nil {
		if err := k.Load(file.Provider(path), toml.Parser()); err != nil {
			return nil, err
		}
	}

	// Env vars with HOST__ prefix, double underscore separates nesting levels.
	// e.g. HOST__OAUTH__CLIENT_ID -> oauth.client_id
	if err := k.Load(env.Provider("HOST__", ".", func(s string) string {
		s = strings.TrimPrefix(s, "HOST__")
		s = strings.ToLower(s)
		s = strings.ReplaceAll(s, "__", ".")
		return s
	}), nil); err != nil {
		return nil, err
	}

	var cfg Config
	if err := k.Unmarshal("", &cfg); err != nil {
		return nil, err
	}

	if cfg.Server.Addr == "" {
		cfg.Server.Addr = ":8080"
	}
	if cfg.Server.StaticDir == "" {
		cfg.Server.StaticDir = "./public"
	}
	if cfg.Auth.Mode == "" {
		cfg.Auth.Mode = "any"
	}

	return &cfg, nil
}

func (c *Config) LogStartup() {
	log.Printf("Listening on %s", c.Server.Addr)
	log.Printf("Serving static files from %s", c.Server.StaticDir)
	log.Printf("Auth mode: %s", c.Auth.Mode)
}
