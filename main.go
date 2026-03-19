package main

import (
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
)

func main() {
	configPath := "config.toml"
	if _, err := os.Stat("config.local.toml"); err == nil {
		configPath = "config.local.toml"
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	oc := newOAuthConfig(&cfg.OAuth)
	r := chi.NewRouter()

	// Auth routes (no session required)
	r.Get("/auth/login", handleLogin(oc))
	r.Get("/auth/callback", handleCallback(oc, cfg))
	r.Get("/auth/logout", handleLogout())

	// Static files behind session middleware
	fileServer := http.FileServer(http.Dir(cfg.Server.StaticDir))
	r.Group(func(r chi.Router) {
		r.Use(sessionMiddleware(cfg.Server.SessionSecret))
		r.Handle("/*", fileServer)
	})

	cfg.LogStartup()
	if err := http.ListenAndServe(cfg.Server.Addr, r); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
