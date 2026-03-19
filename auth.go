package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

const sessionCookieName = "session"
const sessionMaxAge = 14 * 24 * 3600 // 2 weeks

type sessionPayload struct {
	Email  string `json:"email"`
	Expiry int64  `json:"expiry"`
}

func newOAuthConfig(cfg *OAuthConfig) *oauth2.Config {
	oc := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Scopes:       cfg.Scopes,
	}

	switch cfg.Provider {
	case "google":
		oc.Endpoint = google.Endpoint
	default:
		oc.Endpoint = github.Endpoint
	}

	return oc
}

// signSession creates a base64-encoded payload + HMAC signature.
func signSession(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	sig := mac.Sum(nil)
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	sigEncoded := base64.RawURLEncoding.EncodeToString(sig)
	return encoded + "." + sigEncoded
}

// verifySession checks the HMAC and returns the payload if valid.
func verifySession(cookie string, secret string) (*sessionPayload, error) {
	parts := strings.SplitN(cookie, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid session format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expected := mac.Sum(nil)
	if !hmac.Equal(sig, expected) {
		return nil, fmt.Errorf("invalid signature")
	}

	var sp sessionPayload
	if err := json.Unmarshal(payload, &sp); err != nil {
		return nil, err
	}

	if time.Now().Unix() > sp.Expiry {
		return nil, fmt.Errorf("session expired")
	}

	return &sp, nil
}

func setSessionCookie(w http.ResponseWriter, email string, secret string) {
	sp := sessionPayload{
		Email:  email,
		Expiry: time.Now().Unix() + sessionMaxAge,
	}
	payload, _ := json.Marshal(sp)
	value := signSession(payload, secret)

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   sessionMaxAge,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
}

func isEmailAllowed(email string, cfg *AuthConfig) bool {
	if cfg.Mode == "any" {
		return true
	}

	emailLower := strings.ToLower(email)
	for _, allowed := range cfg.AllowedEmails {
		if strings.ToLower(allowed) == emailLower {
			return true
		}
	}

	parts := strings.SplitN(emailLower, "@", 2)
	if len(parts) == 2 {
		domain := parts[1]
		for _, allowed := range cfg.AllowedDomains {
			if strings.ToLower(allowed) == domain {
				return true
			}
		}
	}

	return false
}

// fetchGitHubEmail calls the GitHub API to get the user's primary verified email.
func fetchGitHubEmail(token *oauth2.Token) (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("github emails API returned %d: %s", resp.StatusCode, body)
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", err
	}

	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}

	// Fallback: first verified email
	for _, e := range emails {
		if e.Verified {
			return e.Email, nil
		}
	}

	return "", fmt.Errorf("no verified email found")
}

// fetchGoogleEmail calls the Google userinfo API to get the user's email.
func fetchGoogleEmail(token *oauth2.Token) (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("google userinfo API returned %d: %s", resp.StatusCode, body)
	}

	var info struct {
		Email         string `json:"email"`
		VerifiedEmail bool   `json:"verified_email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return "", err
	}

	if info.Email == "" {
		return "", fmt.Errorf("no email returned from Google")
	}

	return info.Email, nil
}

// fetchEmail fetches the user's email using the appropriate provider API.
func fetchEmail(provider string, token *oauth2.Token) (string, error) {
	switch provider {
	case "google":
		return fetchGoogleEmail(token)
	default:
		return fetchGitHubEmail(token)
	}
}

const redirectCookieName = "oauth_redirect"

func handleLogin(oc *oauth2.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Save the original URL to redirect back after auth
		redirectTo := r.URL.Query().Get("redirect")
		if redirectTo == "" {
			redirectTo = "/"
		}
		http.SetCookie(w, &http.Cookie{
			Name:     redirectCookieName,
			Value:    redirectTo,
			Path:     "/",
			MaxAge:   300,
			HttpOnly: true,
		})

		var opts []oauth2.AuthCodeOption
		if r.URL.Query().Get("prompt") == "select_account" {
			opts = append(opts, oauth2.SetAuthURLParam("prompt", "select_account"))
		}

		url := oc.AuthCodeURL("state", opts...)
		http.Redirect(w, r, url, http.StatusFound)
	}
}

func handleCallback(oc *oauth2.Config, cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "missing code", http.StatusBadRequest)
			return
		}

		token, err := oc.Exchange(r.Context(), code)
		if err != nil {
			log.Printf("OAuth exchange error: %v", err)
			http.Error(w, "OAuth exchange failed", http.StatusInternalServerError)
			return
		}

		email, err := fetchEmail(cfg.OAuth.Provider, token)
		if err != nil {
			log.Printf("Failed to fetch email: %v", err)
			http.Error(w, "Failed to fetch email", http.StatusInternalServerError)
			return
		}

		if !isEmailAllowed(email, &cfg.Auth) {
			log.Printf("Access denied for email: %s", email)
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, `<h1>Access Denied</h1><p>The account <b>%s</b> is not allowed.</p><p><a href="/auth/login?prompt=select_account">Try another account</a></p>`, email)
			return
		}

		setSessionCookie(w, email, cfg.Server.SessionSecret)

		redirectTo := "/"
		if c, err := r.Cookie(redirectCookieName); err == nil && c.Value != "" {
			redirectTo = c.Value
		}
		// Clear the redirect cookie
		http.SetCookie(w, &http.Cookie{
			Name:   redirectCookieName,
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})

		http.Redirect(w, r, redirectTo, http.StatusFound)
	}
}

func handleLogout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clearSessionCookie(w)
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("Logged out"))
	}
}

func sessionMiddleware(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(sessionCookieName)
			if err != nil || cookie.Value == "" {
				redirectToLogin(w, r)
				return
			}

			_, err = verifySession(cookie.Value, secret)
			if err != nil {
				redirectToLogin(w, r)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func redirectToLogin(w http.ResponseWriter, r *http.Request) {
	target := "/auth/login?redirect=" + r.URL.RequestURI()
	http.Redirect(w, r, target, http.StatusFound)
}
