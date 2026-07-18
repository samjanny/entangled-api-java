# Security policy

The `entangled-api-java` verifier implements cryptographic, parsing, schema,
origin-binding, and state-policy checks that are security-critical to the
Entangled v1.0 protocol.

## Reporting a vulnerability

Do not open a public issue or discussion for a suspected vulnerability.

1. Prefer [GitHub private vulnerability reporting](https://github.com/samjanny/entangled-api-java/security/advisories/new).
2. If that channel is unavailable, email `samjanny@gmail.com` with a subject
   beginning `[entangled-api-java security]`.

Include the affected version or commit, the impacted validation stage, the
security consequence, and any known constraints on exploitability. Do not
include sensitive payloads in public channels.

## Response targets

The maintainers aim to acknowledge reports within 3 business days and provide
an initial assessment within 7 business days. Fix and disclosure timing will be
coordinated privately, with a 90-day disclosure window as the default maximum.

## Scope

In scope are the verifier, its public API, the vendored conformance corpus, and
the build and supply-chain configuration that affects published artifacts.
Stateful client behavior explicitly outside the verifier's documented scope,
third-party transports, and unrelated applications are out of scope.

Please report specification-level issues privately through the upstream
[`samjanny/entangled`](https://github.com/samjanny/entangled) repository.
