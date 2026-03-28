# go-dlp-engine

A lightweight Data Loss Prevention (DLP) engine that scans free-form text for sensitive data patterns and produces redacted output — built entirely with the Go standard library.

## Features

- **7 built-in detection patterns** (P001–P007) covering identity, financial, credential, contact, and network data
- **Priority-ordered matching with span deduplication** — higher-priority patterns claim byte ranges first, preventing a long digit sequence (e.g. an 18-digit ID card number) from being partially re-matched as a phone number
- **Bilingual responses** — pattern names and descriptions in both Chinese (`zh`) and English (`en`)
- **Smart masking** — each pattern applies a purpose-built masking strategy (partial reveal, domain preservation, key-only exposure, etc.)
- **Two modes**: `/scan` (detect and report) and `/desensitize` (replace in-place)
- **Zero external dependencies** — uses only the Go standard library (`regexp`, `encoding/json`, `net/http`)

## Detection Patterns

| ID   | Severity | Category   | Pattern |
|------|----------|------------|---------|
| P001 | high     | identity   | Chinese mainland mobile phone number (`1[3-9]XXXXXXXXX`, optional `+86`/`0086` prefix) |
| P002 | high     | identity   | Chinese ID card number (18-digit with Luhn-style check digit) |
| P003 | high     | financial  | Bank card number (UnionPay 62-prefix, Visa 4-prefix, Mastercard 51–55 prefix) |
| P004 | medium   | contact    | Email address |
| P005 | low      | network    | IPv4 address |
| P006 | medium   | credential | JWT Token (`eyJ…`) |
| P007 | high     | credential | Plaintext credential/secret (`password=`, `api_key:`, `access_token=`, etc.) |

## API

### `POST /scan`

Scan text and return a structured finding report. The original text is **not** modified.

**Request**

```json
{
  "text": "Contact: 13812345678, email: user@example.com, ID: 110101199001011234",
  "locale": "en"
}
```

- `text` — text to scan (max 10000 chars)
- `locale` — `"zh"` (default) or `"en"`

**Response**

```json
{
  "success": true,
  "findings": [
    {
      "patternId": "P002",
      "name": "Chinese ID Card",
      "severity": "high",
      "category": "identity",
      "description": "Chinese ID card number detected, highly sensitive personal information.",
      "count": 1,
      "samples": ["110101********1234"]
    },
    {
      "patternId": "P001",
      "name": "Mobile Phone Number",
      "severity": "high",
      "category": "identity",
      "description": "Chinese mainland mobile phone number detected, may involve user privacy exposure.",
      "count": 1,
      "samples": ["138****5678"]
    },
    {
      "patternId": "P004",
      "name": "Email Address",
      "severity": "medium",
      "category": "contact",
      "description": "Email address detected, may involve exposure of user contact information.",
      "count": 1,
      "samples": ["u***@example.com"]
    }
  ],
  "totalCount": 3,
  "riskLevel": "high"
}
```

`riskLevel` is `"high"` / `"medium"` / `"low"` / `"none"`, derived from the highest severity finding.

### `POST /desensitize`

Scan text and return a redacted copy with all sensitive values replaced in-place.

**Request**

```json
{
  "text": "password=MySecret123 user 13812345678",
  "locale": "en"
}
```

**Response**

```json
{
  "success": true,
  "desensitized": "password=*** user 138****5678",
  "replacements": [
    {
      "patternId": "P007",
      "name": "Credential / Secret",
      "count": 1
    },
    {
      "patternId": "P001",
      "name": "Mobile Phone Number",
      "count": 1
    }
  ],
  "totalCount": 2
}
```

### `GET /health`

Returns `200 OK` with body `ok`. Used for container health checks.

## Quick Start

### go run

```bash
git clone https://github.com/bingcs/go-dlp-engine.git
cd go-dlp-engine
go run .
# Listening on :8082
```

### make

```bash
make run          # go run .
make build        # builds to build/dlp-engine
make build-linux  # cross-compile linux/amd64 + darwin/arm64
make vet          # go vet ./...
```

### Docker (optional)

```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o dlp-engine .

FROM alpine:3.19
COPY --from=builder /app/dlp-engine /usr/local/bin/
EXPOSE 8082
CMD ["dlp-engine"]
```

```bash
docker build -t dlp-engine .
docker run -p 8082:8082 dlp-engine
```

## Usage on bingcs.com

This engine powers two interactive tools on [bingcs.com](https://bingcs.com):

- **Sensitive Data Scanner** — paste any text and get a structured risk report
  Read the write-up: [Sensitive Data Scanner — How It Works](https://bingcs.com/blog/2026-03-28-sensitive-data-scanner)

- **Log Desensitizer** — paste log lines and get a redacted copy safe to share
  Read the write-up: [Log Desensitizer — How It Works](https://bingcs.com/blog/2026-03-28-log-desensitizer)

## Technical Implementation

- **Zero dependencies** — all regex compilation, HTTP serving, and JSON encoding use only the Go standard library
- **Pattern ordering matters** — patterns are registered in a specific order so that more specific patterns (ID card 18 digits, bank card with known prefixes) are evaluated before general ones (phone number 11 digits). This prevents a long numeric string from being partially claimed by a lower-priority pattern
- **Span overlap deduplication** (`/scan` mode) — each regex match returns byte index pairs `[start, end]`. After a match is accepted it is recorded in `usedSpans`. Subsequent patterns skip any match whose range overlaps an already-claimed span
- **Independent replacement** (`/desensitize` mode) — patterns run sequentially on the accumulated result string using `ReplaceAllStringFunc`, relying on the ordering guarantee rather than span tracking (the already-masked output won't re-match)
- **Per-pattern masking strategies** — each pattern ID maps to a dedicated masking function: partial reveal for phones and IDs, domain preservation for emails, first-octet reveal for IPs, header-only for JWTs, key-name preservation for credentials

## Future Plans

- Additional patterns: passport numbers, driving licence numbers, IPv6 addresses, AWS/GCP/Azure credential strings
- Custom pattern registration via JSON config
- Allowlist support (skip known-safe values)
- Confidence scoring per match
- OpenTelemetry tracing support
