# Threat model

## Security objective

Keep an educational network-exposure explanation bounded to explicitly
authorized private or loopback hosts, and keep scanner/model output from being
mistaken for proof of compromise or vulnerability.

## Trust boundaries

| Boundary | Untrusted input | Control |
|---|---|---|
| Browser to API | target, authorization checkbox | literal-IP parsing, private/loopback allowlist, explicit authorization |
| Nmap to application | protocol and service labels | small normalized schema, strict service-token validation |
| Application to model | normalized scan JSON | explicit untrusted-data framing, no tools, bounded output, `store=False` |
| Model to browser | generated explanation | rendered as plain text, not HTML |

## Material threats and residual risk

- **Unauthorized scanning:** public addresses and hostnames are rejected, but a
  private address can still belong to another party. The authorization checkbox
  is a policy gate, not proof of ownership.
- **Prompt injection through scanner metadata:** service labels are restricted to
  short token-like values and the prompt treats all JSON as data. The synthetic
  canary fixture checks the deterministic path; model behavior must still be
  evaluated separately.
- **Hallucinated security findings:** explanations are required to distinguish an
  open port from a vulnerability. The offline evaluator flags unsupported ports
  and strong overclaims, but its phrase list is intentionally incomplete.
- **False reassurance:** a top-100 scan is not exhaustive. Every explanation must
  state the limitation and recommend verification.
- **Sensitive data disclosure:** the model receives IP and normalized open-port
  metadata when enabled. Operators should use only non-sensitive lab data and
  review their provider retention requirements.

## Out of scope

Internet scanning, exploitation, vulnerability confirmation, credential use,
production multi-user deployment, and assurance against every prompt-injection
strategy are outside this prototype.
