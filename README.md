# entangled-api-java

[![CI](https://github.com/samjanny/entangled-api-java/actions/workflows/ci.yml/badge.svg)](https://github.com/samjanny/entangled-api-java/actions/workflows/ci.yml)
[![Conformance](https://img.shields.io/badge/corpus-62%2F62-brightgreen)](src/test/java/org/entangled/ConformanceTest.java)
[![Spec](https://img.shields.io/badge/spec-v1.0--rc.27-blue)](https://github.com/samjanny/entangled)
[![Java](https://img.shields.io/badge/Java-21-orange)](pom.xml)
[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue)](#license)

An independent Java reference implementation of the **Entangled v1.0** protocol,
built solely from the specification at
[`samjanny/entangled`](https://github.com/samjanny/entangled) tag `v1.0-rc.27`
(its `specs/`, `docs/`, and `corpus/`), without reference to any other
implementation.

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

Passes the full conformance corpus: **62 / 62 vectors** match the recorded
verdict, diagnostic code, and structured `details` byte-identically.

> Note on vector count: the corpus at `v1.0-rc.27` contains **62** vectors
> (`corpus.json` `rc_target: 1.0-rc.27`). Some older release notes refer to "60
> vectors"; the additional vectors are the rc.25-rc.27 additions (the
> manifest-updated future-skew, the runtime-pubkey resurrection, and the
> migration trio). This implementation targets the rc.27 corpus.

## Building and testing

Requires JDK 21 and Maven. The conformance corpus is checked in under
`src/test/resources/corpus` and is read as raw bytes (no normalization).

```sh
export JAVA_HOME=/path/to/jdk-21
mvn test                          # all unit tests + the 62-vector conformance suite
mvn test -Dtest=ConformanceTest   # the code-vs-corpus conformance suite only
```

CI (`.github/workflows/ci.yml`) runs both on every push.

## Design notes

- **No third-party crypto.** Ed25519 verification, JCS canonicalization,
  base64url, SHA, BIP-39 PIP derivation, and Tor v3 address decoding are all
  implemented in-tree for byte-level control. The JDK's built-in Ed25519
  (`SunEC`) does not implement the strict `verify_strict` profile section 05
  mandates (small-order rejection for both `A` and `R`, canonical `R`, `S < L`,
  cofactorless equation), so verification is hand-implemented over
  `BigInteger` field arithmetic.
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

## Ambiguities found

Per the spec's ambiguity protocol, genuine ambiguities encountered at the Java
boundary -- points where two conforming implementations could diverge with no
clear non-conformance, and which no corpus vector constrains -- were filed as
issues against `samjanny/entangled`:

- **AMB-10** (issue #11): the diagnostic for a bad `origin.carrier` value
  (e.g. `"i2p"`) is not pinned -- `E_SCHEMA_FIELD_SYNTAX` vs
  `E_SCHEMA_ENUM_VIOLATION`. This implementation chose `E_SCHEMA_ENUM_VIOLATION`.
- **AMB-11** (issue #12): the stage/code for an uppercase or otherwise
  non-canonical `origin.address` is not pinned -- Stage 5
  `E_SCHEMA_FIELD_SYNTAX` vs Stage 9 `E_BIND_ORIGIN`. This implementation chose
  Stage 5 `E_SCHEMA_FIELD_SYNTAX`.

Each chosen reading is documented in a code comment citing the spec passages
that motivated it.

## Layout

```
src/main/java/org/entangled/
  DiagnosticCode, Diagnostic, Verdict, RejectException   normative codes and outcomes
  json/        strict JSON lexer/parser, JCS canonicalization
  crypto/      strict Ed25519, base64url, SHA, BIP-39 PIP, Tor v3 address
  schema/      closed-schema field/block/document validators (Stage 5)
  pipeline/    the 10-stage validation pipeline and per-stage logic
src/test/java/org/entangled/
  ConformanceTest    drives all 62 corpus vectors
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
