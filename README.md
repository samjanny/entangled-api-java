# entangled-api-java

[![CI](https://github.com/samjanny/entangled-api-java/actions/workflows/ci.yml/badge.svg)](https://github.com/samjanny/entangled-api-java/actions/workflows/ci.yml)
[![Conformance](https://img.shields.io/badge/corpus-74%2F74-brightgreen)](src/test/java/org/entangled/ConformanceTest.java)
[![Spec](https://img.shields.io/badge/spec-v1.0--rc.37-blue)](https://github.com/samjanny/entangled)
[![Java](https://img.shields.io/badge/Java-21-orange)](pom.xml)
[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue)](#license)

A Java reference implementation of the **Entangled v1.0** protocol,
built from the specification at
[`samjanny/entangled`](https://github.com/samjanny/entangled) tag `v1.0-rc.37`
(its `specs/`, `docs/`, and `corpus/`).

## Usage

The library validates a fetched Entangled document end to end (sections 02-11)
and returns a normative outcome. You give it the raw response bytes plus the
fetch context a client already holds, and get back an accept or a reject carrying
the section 11 diagnostic code and its structured details.

```java
import org.entangled.Verdict;
import org.entangled.pipeline.Context;
import org.entangled.pipeline.Pipeline;
import org.entangled.pipeline.Stage4Kind;

// Verify a manifest fetched from /manifest.json over a Tor v3 onion origin.
Context ctx = new Context(nowEpochSeconds);          // your trusted current time
ctx.expectedKind = Stage4Kind.Kind.MANIFEST;         // known from the fetch endpoint
ctx.fetchedOriginAddress = "<56-char-onion>.onion";  // the address you connected to

Verdict verdict = new Pipeline(ctx).run(manifestBytes);

if (verdict.isAccepted()) {
    // The manifest is valid, current, and origin-bound: render under it.
} else {
    DiagnosticCode code = verdict.diagnostic().code();      // e.g. E_BIND_ORIGIN
    Map<String, Object> details = verdict.diagnostic().details();
}
```

A content document is verified against the runtime key the current manifest
authorizes, and against the path it was fetched from:

```java
Context ctx = new Context(nowEpochSeconds);
ctx.expectedKind = Stage4Kind.Kind.CONTENT;
ctx.fetchedPath = "/articles/first-post";            // byte-exact path binding
ctx.expectedRuntimePubkey = "<base64url runtime key>";

Verdict verdict = new Pipeline(ctx).run(contentBytes);
```

`Context` carries the rest of what a real client holds when it matters: the
submit path and body for transaction binding (`submitPath`, `submitBody`), prior
verified manifests for anti-downgrade and canary checks (`publisherHistory`), and
the successor manifest for migration scenarios (`successorManifest`). Fields left
unset simply skip the checks that depend on them.

Outcomes are exhaustive and machine-readable: `Verdict.isAccepted()`, and on a
rejection `verdict.diagnostic().code()` (a `DiagnosticCode` enum value carrying
its severity and pipeline stage) plus `verdict.diagnostic().details()`.

There are no runtime dependencies; add the built jar to your classpath. Requires
Java 21 at runtime.

See `src/test/java/org/entangled/UsageExampleTest.java` for these snippets as
runnable tests.

## Status

Passes the full conformance corpus: **74 / 74 vectors** match the recorded
verdict, diagnostic code, and structured `details` byte-identically.

> Note on vector count: the corpus at `v1.0-rc.37` contains **74** vectors
> (`corpus.json` `rc_target: 1.0-rc.37`). This implementation tracks the rc.37
> corpus, including the rc.30-rc.33 ambiguity-resolution vectors (AMB-13
> through AMB-17) and the rc.34-rc.37 coverage additions: transaction
> `request_id` binding, `submit_form` label NFC, the dedicated state-update
> codes (`E_STATE_VALUE_SIZE` / `E_STATE_TTL`), and carrier link URL host
> validation.

## Known limitations

### Content index (`content_root`) not yet validated

This implementation does **not** yet implement the section 10 content-index
flow. When a manifest carries `content_root`, a conforming client must fetch
`/content_index.json` from the same carrier origin, verify its SHA-256 against
the `content_root` committed in the manifest, and then verify every content
document's `(seq, hash)` against that index before rendering. This library
validates `content_root` only for syntax (a `sha-256:` digest in the manifest
schema) and does not perform the fetch, the hash binding, or the per-document
`seq` / `hash` checks. The section 11 codes for this flow
(`E_CONTENT_INDEX_FETCH_FAILED`, `E_CONTENT_INDEX_HASH_MISMATCH`,
`E_CONTENT_INDEX_INVALID`, `E_CONTENT_SEQ_MISSING`, `E_CONTENT_SEQ_ROLLBACK`,
`E_CONTENT_SEQ_UNCOMMITTED`, `E_CONTENT_HASH_MISMATCH`) are present in
`DiagnosticCode` but are not yet reachable.

**Security implication.** The content index is the defense against a
`K_runtime`-only attacker: an adversary who has compromised the runtime signing
key but not the publisher key. Because `content_root` is signed by
`K_publisher`, it binds the set of valid content documents `(path, seq, hash)`
under the publisher's signature, which a runtime-key-only attacker cannot forge.
A client that verifies the index rejects an older signed version of a document
(`E_CONTENT_SEQ_ROLLBACK`), a forged higher-sequence update
(`E_CONTENT_SEQ_UNCOMMITTED`), and a substituted body at the committed sequence
(`E_CONTENT_HASH_MISMATCH`); section 10 treats a manifest that commits to a
content index but cannot deliver a valid one as a hard security failure,
"indistinguishable from server compromise". Without this flow, a site that
declares `content_root` is rendered by this library with content protected only
by the `K_runtime` signature, so a runtime-key-only attacker could serve
rolled-back or forged content that a content-index-validating client would
reject. Sites that do not declare `content_root` are unaffected.

**Recommendation.** If you need content-index enforcement, use the Rust
reference implementation
([`samjanny/entangled-api`](https://github.com/samjanny/entangled-api)), which
implements the full flow, or do not rely on this library to render content from
sites that declare `content_root` until the feature lands. Tracked as a future
tranche (see the repository issues).

## Building and testing

Requires JDK 21 and Maven. The conformance corpus is checked in under
`src/test/resources/corpus` and is read as raw bytes (no normalization).

```sh
export JAVA_HOME=/path/to/jdk-21
mvn test                          # all unit tests + the 74-vector conformance suite
mvn test -Dtest=ConformanceTest   # the code-vs-corpus conformance suite only
```

CI (`.github/workflows/ci.yml`) runs both on every push.

## Design notes

- **No hand-rolled crypto primitives.** Ed25519 verification and SHA delegate to
  the JDK (`SunEC`, `MessageDigest`); JCS canonicalization, base64url, BIP-39 PIP
  derivation, and Tor v3 address decoding are implemented in-tree (they are
  encodings, not cryptographic primitives). For Ed25519 the JDK provides the curve
  arithmetic, SHA-512, the canonical-`S` (`S < L`) check, canonical point-encoding
  rejection, and the cofactorless verification equation section 05:178 mandates.
  `SunEC` does not reject small-order points, so `Ed25519` adds the one missing
  strict-profile check (small-order rejection of both `A` and `R`, section 05:174)
  as a thin layer over the JDK verifier, exactly as section 05:180 directs. The
  small-order check is a constant-table comparison, not curve arithmetic. The
  result matches `ed25519-dalek` `verify_strict` on all 15 `ed25519-speccheck`
  vectors, which `CryptoTest` pins.
- **First-failing-stage precedence** (section 10) is enforced by running the
  10-stage pipeline in order and converting the first stage's rejection into the
  verdict.
- **The integer grammar** (section 04) is validated as a whole-document Stage 5
  pre-pass, before closed-schema field-presence checks, to honor the spec's
  requirement that numeric tokens are validated "before any conversion"; corpus
  vector 140 fixes this ordering.
- **The Stage 2 byte cap** is selected by the expected document kind from the
  fetch context (a real client knows whether it fetched `/manifest.json`, a
  content path, or a submit response), since the kind-specific cap is enforced
  before parsing.

## Layout

```
src/main/java/org/entangled/
  DiagnosticCode, Diagnostic, Verdict, RejectException   normative codes and outcomes
  json/        strict JSON lexer/parser, JCS canonicalization
  crypto/      strict Ed25519, base64url, SHA, BIP-39 PIP, Tor v3 address
  schema/      closed-schema field/block/document validators (Stage 5)
  pipeline/    the 10-stage validation pipeline and per-stage logic
src/test/java/org/entangled/
  ConformanceTest    drives all 74 corpus vectors
  unit tests for the JSON, JCS, crypto, and schema layers
src/test/resources/corpus/    the spec conformance corpus, verbatim
```

## License

Dual-licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. See [LICENSE.md](LICENSE.md) for details. The bundled
conformance corpus under `src/test/resources/corpus` is copied verbatim from the
upstream specification and retains the licensing of that project.
