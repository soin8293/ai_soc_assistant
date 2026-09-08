# AI SOC Assistant

[![CI](https://github.com/soin8293/ai_soc_assistant/actions/workflows/ci.yml/badge.svg)](https://github.com/soin8293/ai_soc_assistant/actions)

A bounded educational Python/FastAPI prototype that performs a limited Nmap
scan on an explicitly authorized loopback or private-network IP address and
turns normalized open-port metadata into cautious, plain-language guidance.

SOC stands for security operations center. This educational assistant is **not** a security
operations center, vulnerability scanner, incident-detection system, or
complete security assessment.

## What it demonstrates

- Server-side validation of literal IP targets against a narrow allowlist
- Explicit confirmation that the caller is authorized to scan the target
- A limited Nmap top-100-port profile without scripts or exploitation
- Normalization of untrusted scan metadata before model input
- OpenAI Responses API integration with `store=False`
- A deterministic local explanation when no API key is configured
- Tests that use a fake scanner and never scan a network or call OpenAI
- Plain-text browser rendering to avoid injecting model output as HTML
- Synthetic explanation fixtures and an inspectable offline quality evaluator

The OpenAI integration follows the official
[Responses API](https://developers.openai.com/api/reference/cli/resources/responses/methods/create)
shape and reads credentials from `OPENAI_API_KEY` rather than source code.

## Safety boundary

The backend accepts only:

- IPv4 loopback (`127.0.0.0/8`)
- RFC1918 IPv4 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
- IPv6 loopback (`::1`)
- IPv6 unique-local addresses (`fc00::/7`)

Hostnames, public IPs, and link-local IPs are rejected. This allowlist reduces
risk but does not grant permission: use the tool only on systems you own or are
explicitly authorized to test.

## Architecture

```text
browser form
    │ target + authorization confirmation
    ▼
FastAPI validation ── rejects hostnames/public targets
    │
    ▼
limited Nmap scan ── normalizes open port/protocol/service fields
    │
    ├── no OPENAI_API_KEY ── deterministic local guidance
    │
    └── configured key ── OpenAI Responses API ── plain-text explanation
```

## Setup

Install the Nmap command-line tool first. Then:

```bash
git clone https://github.com/soin8293/ai_soc_assistant.git
cd ai_soc_assistant
python -m venv .venv
# Activate .venv using the command for your shell.
python -m pip install -r requirements.txt
python -m uvicorn main:app --reload
```

Open <http://127.0.0.1:8000>. Without an OpenAI key, the application remains
usable and returns a local rule-based explanation.

For model-assisted explanations:

```bash
# Copy .env.example values into your shell or secret manager.
export OPENAI_API_KEY="your-project-key"
export OPENAI_MODEL="gpt-4.1-mini"
```

PowerShell:

```powershell
$env:OPENAI_API_KEY = "your-project-key"
$env:OPENAI_MODEL = "gpt-4.1-mini"
```

Never commit a real key. `.env` files are excluded; `.env.example` contains
placeholders only.

## Tests

```bash
python -m pip install -r requirements.txt -r requirements-dev.txt
python -m pytest -q
```

The test suite verifies target boundaries, normalized scan output, local
fallback behavior, and authorization enforcement. It uses no real network scan
and no OpenAI request.

Run the synthetic explanation benchmark separately:

```bash
python scripts/run_evaluation.py
```

The committed `results/local-baseline.json` records the deterministic baseline.
The score is a diagnostic summary—not a validated scientific instrument—and
the case-level findings remain the primary evidence. See
[`docs/threat-model.md`](docs/threat-model.md) for trust boundaries and residual
risk.

## Limitations

- An open port is not automatically a vulnerability.
- Only Nmap's top 100 ports are checked; results are intentionally incomplete.
- Service names are scanner hints, not verified software identity or version.
- Model explanations can be incomplete or wrong and must be verified.
- No authentication, multi-user isolation, persistence, rate limiting,
  production deployment, or formal security review is provided.

## AI-assistance disclosure

The 2026 safety and API modernization was produced with OpenAI Codex assistance
at Sorbarikor Inene's direction. Portfolio descriptions should continue to
distinguish the original educational prototype, AI-assisted implementation,
and independently verified test results.

## Author

Sorbarikor Inene — [@soin8293](https://github.com/soin8293)

## License

MIT. See [`LICENSE`](LICENSE).
