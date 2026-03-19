# Auth Host

Static file server with OAuth 2.0 authentication. Protect internal tools behind Google or GitHub login — restrict access by email or domain, no code changes required.

## Install

```bash
go build -o host .
./host
```

Or with Docker:

```bash
docker compose up
```

## Quick Start

Copy `config.toml` and fill in your OAuth credentials:

```toml
[server]
addr = ":8080"
static_dir = "./public"
session_secret = "your-random-secret"

[oauth]
provider = "google"
client_id = "your-client-id"
client_secret = "your-client-secret"
redirect_url = "http://localhost:8080/auth/callback"
scopes = ["https://www.googleapis.com/auth/userinfo.email"]

[auth]
mode = "whitelist"
allowed_domains = ["yourcompany.com"]
```

Drop your static files into `./public` and run. Only users with a matching email or domain get through.

## Configuration

All settings can be set via environment variables using the `HOST__` prefix and `__` for nesting:

```bash
HOST__OAUTH__PROVIDER=github
HOST__OAUTH__CLIENT_ID=abc123
HOST__OAUTH__CLIENT_SECRET=secret
HOST__AUTH__MODE=whitelist
HOST__AUTH__ALLOWED_DOMAINS=yourcompany.com
```

Environment variables override `config.toml`.

## Auth Modes

- `any` — any authenticated user is allowed
- `whitelist` — only specific emails or domains

```toml
[auth]
mode = "whitelist"
allowed_emails = ["alice@example.com"]
allowed_domains = ["yourcompany.com"]
```

## OAuth Providers

- `google` — uses Google userinfo API
- `github` — uses GitHub emails API

## Routes

| Route | Description |
|---|---|
| `GET /auth/login` | Start OAuth flow |
| `GET /auth/callback` | OAuth callback |
| `GET /auth/logout` | Clear session |
| `GET /*` | Serve static files (requires auth) |

## Features

- Google and GitHub OAuth support
- Email whitelist and domain-based access control
- HMAC-signed session cookies (2-week expiry)
- TOML config with environment variable overrides
- Single static binary, no external dependencies
- Docker-ready with multi-stage build

## License

MIT
