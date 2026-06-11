# entangled-api-java

[![CI](https://github.com/samjanny/entangled-api-java/actions/workflows/ci.yml/badge.svg)](https://github.com/samjanny/entangled-api-java/actions/workflows/ci.yml)
[![Conformance](https://img.shields.io/badge/corpus-109%2F109-brightgreen)](src/test/java/org/entangled/ConformanceTest.java)
[![Spec](https://img.shields.io/badge/spec-v1.0--rc.57-blue)](https://github.com/samjanny/entangled)
[![Java](https://img.shields.io/badge/Java-21-orange)](pom.xml)
[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue)](#license)

A Java reference implementation of the **Entangled v1.0** protocol,
built from the specification at
[`samjanny/entangled`](https://github.com/samjanny/entangled) tag `v1.0-rc.57`
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

Passes the conformance corpus at `v1.0-rc.57` (**140 vectors**): **109 / 109**
in-scope vectors match the recorded verdict, diagnostic code, and structured
`details` byte-identically.

> Note on vector count: the corpus at `v1.0-rc.57` contains **140** vectors
> (`corpus.json` `rc_target: 1.0-rc.57`). Thirty-one of them exercise layers
> that are out of scope for this verifier (see Scope): the Stage 7 trust-state
> machine (`210`, `211`, `215`), the section 03 image resource layer
> (`240`-`245`, `269`), and the Stage 1 transport layer (`250`-`268`, `270`,
> `271`). They are listed in an explicit out-of-scope set in `ConformanceTest`
> and reported with a printed count rather than counted as failures, so 109 of
> the 140 vectors run and all 109 pass.

## Scope

Like the Rust reference crate (`entangled-core`), this library is a **verifier**:
it covers the per-document validation pipeline (section 10 Stages 2 through 9)
and deliberately leaves the section 10 Stage 7 trust-state machine - first
contact, TOFU pinning, external PIP verification, and the Changed/mismatch
detection that rejects a manifest presenting a different `K_publisher.pub` than a
retained identity - to an embedding client layer. Trust-state resolution depends
on retained publisher identity and history persisted across sessions, which is a
stateful client concern rather than a per-document verification concern.

Consequently a manifest signed correctly under a different publisher key is
verified as internally consistent and correctly self-signed, but is not detected
as a trust mismatch: that detection belongs to the client layer that holds the
retained identity. The section 11 codes for this flow (`E_TRUST_MISMATCH`,
`E_TRUST_USER_REJECTED`, `I_TRUST_FIRST_CONTACT`, `I_TRUST_TOFU_PINNED`,
`I_TRUST_VERIFIED`) are present in `DiagnosticCode` for catalog completeness but
are not emitted here.

The conformance corpus exercises this through vectors
`210-trust-publisher-key-mismatch`, `211-trust-user-rejected-new-identity`, and
`215-trust-observed-mismatch`; all are listed in an explicit out-of-scope set in
`ConformanceTest` and reported with a printed count rather than counted as
failures, so the scope boundary stays visible and never silently passes.

**Security implication.** Trust-state resolution is what binds a site to a
stable publisher identity across visits. This library verifies that a manifest
is internally consistent and correctly signed under the `K_publisher.pub` it
presents; it does not detect that the presented key differs from one a client
previously pinned for the same site. An embedding client that needs
publisher-identity continuity (TOFU pinning, PIP verification, mismatch warnings)
must implement that layer on top of this verifier.

**What is implemented.** The content-index flow (`content_root` hash binding and
per-document `seq` / `hash` verification) and the policy-relative state check
(`E_STATE_UNDECLARED`) are implemented and exercised by the corpus. Out of scope
alongside the Stage 7 trust-state layer are the section 03 image resource layer
(fetching, decoding, and the per-image `W_IMAGE_*` outcomes; vectors `240`-`245`
and `269`, driven by the entangled-client image harness) and the Stage 1
transport layer (HTTP response classification against the section 09 wire
profile; vectors `250`-`271`, exercised by mock-response harnesses in
implementations that own a fetch surface).

## Building and testing

Requires JDK 21 and Maven. The conformance corpus is checked in under
`src/test/resources/corpus` and is read as raw bytes (no normalization).

```sh
export JAVA_HOME=/path/to/jdk-21
mvn test                          # all unit tests + the conformance suite (109 in-scope vectors)
mvn test -Dtest=ConformanceTest   # the code-vs-corpus conformance suite only
```

CI (`.github/workflows/ci.yml`) runs both on every push.

## Design notes

- **No hand-rolled crypto primitives.** Ed25519 verification and SHA delegate to
  the JDK (`SunEC`, `MessageDigest`); JCS canonicalization, base64url, BIP-39 PIP
  derivation, and Tor v3 address decoding are implemented in-tree (they are
  encodings, not cryptographic primitives). Only the irreducible curve operations
  are left to the JDK: the on-curve decoding of `A` and `R`, SHA-512, and the
  cofactorless verification equation section 05:178 mandates. Every strict-profile
  accept/reject *policy* is decided by `Ed25519` itself, before delegating, so
  acceptance does not depend on the provider's internal point/scalar handling:
  non-canonical point encodings of `A` and `R` (`y >= p`, section 05:154, 05:168),
  small-order points `A` and `R` (section 05:155, 05:174), and a non-canonical
  scalar `S` (`S >= L`, section 05:169). `SunEC` does not reject the non-canonical
  encodings or small-order points, and although it does reject `S >= L` the layer
  re-checks it so the policy is not delegated. These checks are constant-table or
  integer-bound comparisons, not curve arithmetic, added over the JDK verifier
  exactly as section 05:180 directs. The result matches `ed25519-dalek`
  `verify_strict` on all 15 `ed25519-speccheck` vectors, which `CryptoTest` pins.
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
  ConformanceTest    drives all 140 corpus vectors (109 in scope)
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
