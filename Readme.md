# jsmap

A command-line tool that crawls a web page, collects every JavaScript file
it loads (inline and external), and scans the JS content for leaked
secrets (API keys, tokens, credentials) and interesting links (API
endpoints, cloud storage buckets, internal/staging URLs).

## How it works

1. Visits the target URL with [colly](https://github.com/gocolly/colly)
   and collects every `<script>` tag — inline scripts are scanned
   immediately, external script URLs are queued up.
2. Fetches all external scripts concurrently (bounded worker pool).
3. Runs each file's content against a set of regex rules defined in
   [`templates/js-secrets.toml`](templates/js-secrets.toml) — the same
   format [gitleaks](https://github.com/gitleaks/gitleaks) uses.
4. Splits results into **secrets** and **links** based on each rule's
   tags, deduplicates, and prints both.

## Project structure

```
.
├── cmd/
│   └── root.go        # CLI flags (cobra) + crawl/fetch/scan orchestration
├── internal/
│   └── scanner.go      # rule loading, scanning, filtering (package internal)
├── templates/
│   └── js-secrets.toml # rule set: secrets + interesting-link patterns
├── main.go              # entrypoint, calls cmd.Execute()
├── go.mod
└── go.sum
```

## Install

```bash
go get github.com/spf13/cobra
go get github.com/BurntSushi/toml
go get github.com/gocolly/colly/v2
go build -o jsmap .
```

## Usage

```bash
./jsmap --url https://example.com
```

### Flags

| Flag            | Short | Default                       | Description                          |
|-----------------|-------|--------------------------------|---------------------------------------|
| `--url`         | `-u`  | *(required)*                   | Target URL to scan                    |
| `--rules`       | `-r`  | `templates/js-secrets.toml`    | Path to the rules TOML file           |
| `--concurrency` | `-c`  | `5`                             | Number of concurrent script fetches   |
| `--only` | `-o`  | `secrect\|links`                             | Speficies to their gets secrets or links |

```bash
./jsmap -u https://example.com -r templates/js-secrets.toml -c 10
```

## Output

Results print in two sections:

```
=== Secrets (N) ===
[rule-id] source-url
  -> matched value

=== Links (N) ===
[rule-id] source-url
  -> matched value
```

## Customizing rules

Rules live in `templates/js-secrets.toml`, one `[[rules]]` block per
pattern:

```toml
[[rules]]
id = "example-rule"
description = "What this catches and why it matters"
regex = '''your-regex-here'''
keywords = ["cheap-prefilter-strings"]
tags = ["secret"]   # omit for secret rules — defaults to ["secret"]
                     # use ["link"] for URL/endpoint patterns
```

Add new rules by appending another `[[rules]]` block — no code changes
needed. The `tags` field controls which output section (secrets vs.
links) a match lands in.

## Notes

- `generic-api-key` in the ruleset is the highest-recall, highest-noise
  rule — it's what catches app-specific/custom secrets the named
  provider rules (Stripe, Slack, etc.) miss. Expect to review its hits
  manually.
- Scanning only covers static JS delivered in the initial HTML response.
  Client-rendered SPAs that inject `<script>` tags after JS execution
  will need a headless-browser crawler (e.g. chromedp/go-rod) instead of
  colly to be fully covered.
