# secret-tripwire

PostToolUse hook for Claude Code that scans tool outputs for leaked secrets before they enter the model's context window. Once a secret hits the context, it's effectively leaked to the model. This intercepts it first.

## Install

```bash
npm install -g secret-tripwire
```

## Setup

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": ".*",
        "hooks": [
          {
            "type": "command",
            "command": "secret-tripwire",
            "timeout": 5
          }
        ]
      }
    ]
  }
}
```

## What It Detects

| Secret Type | Pattern | Example |
|-------------|---------|---------|
| AWS Access Key | `AKIA[0-9A-Z]{16}` | `AKIAIOSFODNN7EXAMPLE` |
| GitHub Token | `ghp_`, `gho_`, `ghs_`, `github_pat_` | `ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh` |
| Private Key | `-----BEGIN * PRIVATE KEY-----` | RSA, EC, PGP, OPENSSH, DSA |
| JWT Token | `eyJ...eyJ...` (base64url) | `eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOi...` |
| Connection String | `postgresql://`, `mongodb+srv://`, etc. | `postgresql://user:pass@host/db` |
| API Key | `api_key: "..."`, `secret_key=...` | `api_key: "sk_live_abcdef1234567890"` |
| Bearer Token | `Bearer <40+ chars>` | `Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6...` |

## How It Works

1. Claude Code calls a tool (Read, Bash, WebFetch, etc.)
2. The tool returns output
3. Before the output enters Claude's context, this hook scans it
4. If secrets are detected, a warning is injected via `additionalContext`
5. Claude sees the warning and knows not to repeat the raw output

This is a **PostToolUse** hook — it's advisory (exit 0 always). It cannot block tool execution, only warn after the fact. The warning tells Claude that secrets were detected and the raw output should not be referenced.

## Library Usage

```typescript
import { scan, redact } from 'secret-tripwire'

// Scan text for secrets
const result = scan('My AWS key is AKIAIOSFODNN7EXAMPLE')
console.log(result.clean)       // false
console.log(result.detections)  // [{ type: 'AWS_KEY', match: 'AKIAIОСF...', index: 17 }]

// Redact secrets from text
const { redacted, count } = redact('Key: AKIAIOSFODNN7EXAMPLE')
console.log(redacted) // 'Key: [REDACTED-AWS_KEY]'
console.log(count)    // 1
```

## Design

- **Zero false positives over zero false negatives** — patterns are conservative (high-confidence only)
- **Truncated matches** — detected secrets are truncated to 8 chars in logs so the warning itself doesn't leak
- **Always exits 0** — PostToolUse hooks are advisory, never blocking
- **Zero runtime dependencies** beyond `@valencets/resultkit`

## Requirements

- Node.js >= 22
- ESM only

## License

MIT
