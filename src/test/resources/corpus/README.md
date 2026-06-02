# Entangled v1.0 conformance corpus

Test vectors for Entangled v1.0 protocol implementations.

## Status

This corpus is normative: a v1.0-conforming implementation MUST agree with the verdicts recorded here for each vector. Implementations are encouraged to drive their own conformance test suite from `corpus.json`.

The corpus is generated deterministically from a fixed set of test seeds. Anyone can reproduce it byte-for-byte by running the generator.

## Layout

```
corpus/
+-- README.md          this file
+-- keys.json          public key material derived from fixed test seeds
+-- corpus.json        machine-readable index: vector id, expected verdict, etc.
+-- vectors/
|   `-- <id>/
|       +-- input.json      (or input.bin for non-JSON inputs)
|       `-- ... extra files such as submit_body.json, image bytes
`-- tools/
    `-- generate.py    deterministic generator
```

`corpus.json` is the entry point. Every vector is described by:

- `id` - stable identifier, prefixed with a numeric category (001-099 positive, 100-199 single-document negative diagnostics organized by pipeline stage, 200-299 multi-document scenarios such as migration; the full per-stage breakdown is in the "Categories of vectors" table below);
- `kind` - `manifest`, `content`, or `transaction` (the kind of the primary input document; multi-document scenarios may carry additional documents in `extra_files`);
- `description` - what the vector exercises;
- `spec_refs` - the spec sections the vector tests;
- `input` - relative path to the input bytes of the primary document;
- `expected.verdict` - `accept` or `reject` (for multi-document scenarios such as migration vectors, the verdict refers to the scenario outcome - e.g., the migration adoption - not necessarily the in-isolation validity of the primary document);
- `expected.diagnostic` - for rejections, the normative §11 diagnostic code;
- `expected.diagnostic_details` - for rejections whose §11 diagnostic carries structured `details` (e.g., `E_MIGRATION_MISMATCH` with `mismatch_field` and `underlying_diagnostic_code`), the expected `details` object the implementation should produce;
- `context` - optional fields needed to apply the vector (fetched path, fetched origin address, prerequisites such as a previously verified manifest, the corresponding submit body for transactions, the address and on-disk path of a successor manifest for migration scenarios, etc.). The `previously_verified` field (single path) seeds the client's publisher history with one prior manifest. The `previously_verified_history` field (array of paths in publication order, oldest first) seeds the client's publisher history with a sequence of prior manifests; used by vectors that exercise rules whose scope extends beyond the immediately preceding manifest (for example, the §08 SHOULD-level runtime-pubkey resurrection check, vector 185);
- `extra_files` - additional files in the vector directory (e.g., `submit_body.json` for transactions, `successor_manifest.json` for migration scenarios).

The corpus index also carries a top-level `clock_now` field, in RFC 3339 form. Harnesses MUST mock the implementation's wall clock to this value for the duration of the test run. This is required because canary diagnostics depend on `now` and the corpus uses fixed `issued_at` timestamps; without clock mocking, time-dependent vectors are not reproducible.

## Test keys

`keys.json` records the test-only Ed25519 keypairs derived from fixed 32-byte seeds. The seeds are public ASCII strings (e.g., `b"ENTANGLED-v1.0-publisher-test01\x00"`); the corresponding private keys are NOT secret. They MUST NOT be used for any deployment.

Three roles are pre-derived: `publisher` (`K_publisher`), `runtime` (`K_runtime`), `origin` (`K_origin`). A second runtime keypair (`runtime_2`) is provided for tests that need a distinct `K_runtime.pub` (e.g., the equal-`issued_at` conflict vector). A second origin keypair (`origin_2`) is provided for migration scenarios where the announcing and successor manifests bind to different `K_origin` keys; its Tor v3 onion address is also recorded.

For the `origin` and `origin_2` keypairs, the corresponding Tor v3 onion address is recorded alongside the public key; each address is derived from its public key by the rend-spec-v3 procedure and used for origin-binding in the relevant manifest vectors.

The `publisher` entry in `keys.json` also carries `pip`: the 24-word Publisher Identity Phrase derived from `publisher.pub_b64u` per §05 (BIP-39 English wordlist over the raw 32-byte public key, with an 8-bit SHA-256 checksum). An implementation that derives PIPs MUST produce the same string for this public key. The wordlist used by `generate.py` is bundled at `tools/bip39_english.txt` and is the canonical BIP-39 English wordlist from the Bitcoin BIPs repository (`bitcoin/bips: bip-0039/english.txt`); its SHA-256 is `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`. The `pip` field is omitted when the wordlist file is absent; presence of the field is therefore the indicator that the corpus was regenerated with a verified wordlist in place.

## Diagnostics

Negative vectors carry the normative diagnostic code from §11 of the specification. Where multiple stages could in principle detect the violation, the diagnostic listed is the one the spec assigns (or, for parser-detectable cases, the one whose protocol-level meaning matches the violation regardless of detection stage).

Negative vectors are constructed so that the diagnostic-relevant violation is the only violation in the document at the first failing pipeline stage. After all earlier stages pass cleanly, exactly one diagnostic-relevant violation is intended to be live; later-stage violations may exist in the same document only when they cannot be exercised in isolation (e.g., a placeholder `sig` for a vector whose diagnostic precedes signature verification). This isolation is what makes the expected diagnostic deterministic across conforming implementations: a vector that contains two competing stage-5 violations would permit two equally-conformant rejection codes, defeating the corpus's normative purpose.

## Running the corpus against an implementation

The general test harness pattern:

1. Load `corpus.json`.
2. Set the implementation's wall clock to `corpus.json["clock_now"]` (mock or inject) for the duration of the test run.
3. For each vector:
   - read the raw input bytes from `input` (no normalization, no transcoding);
   - apply implementation-specific context: e.g., set the "fetched path" to `context.fetched_path` for content documents, set the "previously verified manifest" for canary-conflict vectors, etc.;
   - run the input through the implementation's validation pipeline;
   - compare the implementation's outcome against `expected`.

Implementations SHOULD report any vector whose actual outcome diverges from the expected one as a conformance failure.

## Regenerating

```
python3 corpus/tools/generate.py
```

Requires Python 3.10+ and the `cryptography` package (for raw Ed25519 RFC 8032 signing). The generator is fully deterministic; output bytes match across runs and across machines.

## Categories of vectors

| Range | Category |
|---|---|
| 001-099 | Positive (must be accepted) |
| 100-109 | Stage 2 input checks (BOM, UTF-8, byte cap) |
| 110-119 | Stage 3 JSON parsing (duplicate keys, nesting depth, string length, array length, object keys, malformed JSON; and the Stage-3-limit-vs-numeric-grammar precedence vectors 117/118, where a structural limit co-occurs with a non-integer token and the Stage 3 limit code wins) |
| 120-129 | Stage 4 kind discrimination (spec_version, unknown kind, missing required top-level field) |
| 130-139 | Stage 5 schema (unknown field, missing required, null literal, unknown block kind, field type, field range, block not permitted in document kind, duplicate uniqueness-required entry, malformed Unicode, field-specific length cap) |
| 140-142 | Numeric grammar (float, exponent, overflow) |
| 143     | Stage 5 semantic - submit-budget state-policy aggregate overflow |
| 144-145 | Stage 5 origin field (carrier enum violation, non-canonical address syntax) |
| 146-147 | Stage 5 schema (empty mandatory array, nested inline link) |
| 148-149, 169 | Stage 5 transaction state_updates (value over the 4096-byte hard ceiling, ttl outside 300..7776000 including a conforming integer above u32::MAX, both E_STATE_TTL) |
| 150-157 | Stage 6 signature (modified payload, malformed length, non-canonical S, small-order A, non-canonical R, non-canonical A, missing-key context, small-order R) |
| 158, 165-167 | Stage 5 link target URL (carrier URL host not a valid tor-v3 onion address; citation/carrier URL outside the RFC 3986 character set or carrying a malformed percent-encoded triplet) |
| 159     | Stage 5 manifest cross-field reporting precedence (co-occurring E_SUBMIT_BUDGET + E_ORIGIN_INVALID; the submit-budget aggregate is reported first per AMB-28) |
| 160-162 | Strict base64url (padding, alphabet, whitespace) |
| 163-164 | Stage 5 transaction state_updates operation-form schema (unknown `op` closed-enum violation E_SCHEMA_ENUM_VIOLATION, missing operation-form field E_SCHEMA_REQUIRED_FIELD) |
| 168     | Stage 5 schema (null literal as an array element, E_SCHEMA_NULL_VALUE; cf. 132 null object member) |
| 170-179 | Stage 9 binding (path mismatch, reserved path, request_hash, request_id, origin binding, origin not_after semantic constraints including both `reason` values, manifest.updated future-skew) |
| 180-189 | Canary (equal `issued_at` conflict, anti-downgrade, interval-bounds violation, issued_at future-skew, runtime-key reuse) |
| 190-199 | Unicode and canonicalization (NFD vs NFC) |
| 200-209 | Migration scenarios (successor_stage9_failure under `E_MIGRATION_MISMATCH`, including a broken successor that also announces a reverse cycle, pinning the successor-verification vs chain_cycle ordering; chain-cycle, announcement-internal successor_key_mismatch, and the self_pointer Stage-5 precedence vector under `E_MIGRATION_INVALID`; multi-document scenarios carry the successor manifest in `extra_files`) |

Coverage relative to the §11 diagnostic code catalog remains partial. Codes not yet covered in this corpus fall into the following groups:

- **Stage 1 transport** (`E_TRANSPORT_*`, all 13 codes): require an extension of the vector schema to carry expected HTTP response metadata (status code, headers) alongside the body bytes. The pipeline-isolation rule applies normally; only the schema extension is open.
- **Stage 7 trust** (`E_TRUST_MISMATCH`, `E_TRUST_USER_REJECTED`): require multi-manifest scenarios that establish a prior pin and present a different `K_publisher.pub`.
- **Stage 9 binding**: of the transaction binding sub-codes, `E_BIND_REQUEST_ID` is covered by vector 173 -- a transaction whose `request_id` differs from the one the client placed in the submit body, with `in_response_to` and `request_hash` both left matching. The transaction's `request_id` is an independent copied field, not part of the hashed submit body, so a `request_id`-only mismatch isolates cleanly from `E_BIND_REQUEST_HASH`. `E_BIND_RESPONSE_PATH` is not yet covered: it is likewise isolable (a transaction whose `in_response_to` differs from the submit path, with `request_id` and `request_hash` left matching) but deferred to a future tranche, not non-constructible. §10 does not normatively order the Stage-9 sub-checks, so each binding vector keeps a single live violation to stay deterministic across conforming implementations.
- **Stage 9 origin lifecycle**: `E_ORIGIN_EXPIRED` is reachable on a manifest whose `origin.not_after` is past `clock_now`. Per §10 (AMB-12, rc.29) the Expired canary state is not a Stage 8 pipeline halt but a Stage 10 render-block, so a manifest that is simultaneously canary-Expired and origin-expired still reaches Stage 9 and reports `E_ORIGIN_EXPIRED` as the first-failing-stage diagnostic. This co-occurrence is exactly what migration vector 200 (`underlying_diagnostic_code = E_ORIGIN_EXPIRED` on a successor that is both canary-Expired and origin-expired) exercises.
- **`E_CANARY_EXPIRED` runtime emission point**: not yet covered. Per §10 (AMB-12) the Expired canary state is a Stage 10 render-block, not a pipeline-stage rejection: a manifest that is canary-Expired but otherwise passes every stage reaches Stage 10 and is render-blocked (with the §08:185 per-session override), rather than producing an `accept`/`reject` pipeline verdict. Exercising the emission point directly therefore needs the render-state / `expected.warnings`-style schema extension below, not a `reject` vector.
- **Warning-class diagnostics** (`W_CANARY_NEAR_EXPIRATION`, `W_CANARY_GAP`, `W_CANARY_UNAVAILABLE`, all `W_IMAGE_*`, `W_HISTORICAL_RENDERED`): require an `expected.warnings` extension to the vector schema, since warnings coexist with an `accept` verdict. `W_CANARY_EXPIRED` and `W_HISTORICAL_RUNTIME_AMBIGUOUS` were promoted to `E_CANARY_EXPIRED` and `E_HISTORICAL_RUNTIME_AMBIGUOUS` (both error) at rc.23 to align the catalog with the §08:183 and §10 (Historical content authorization) hard-block behavior; they are no longer in this group.
- **Image** (`W_IMAGE_*`, all 7 codes): require image bytes in `extra_files` and an `image_response.json` describing the fetched-content type/length; vector schema extension.
- **State** (`E_STATE_*`): `E_STATE_VALUE_SIZE` and `E_STATE_TTL` are covered by single transaction vectors (148-state-value-size, 149-state-ttl). A transaction's `state_updates` array is validated standalone at Stage 5, so the 4096-byte `value` hard ceiling (§07:170) and the 300..7776000-second `ttl` hard range (§07:279) are exercised with no manifest `state_policy` or submit-flow context. The Stage 5 manifest-validation portion of the submit-budget machinery (`E_SUBMIT_BUDGET` with `details.component = "state"`) is covered by a single-document vector (143-submit-budget-state-overflow), which counts each `value` at its raw `max_size` (UTF-8 byte length, no JSON-escape expansion), consistent with §07 `max_size` as a raw UTF-8 byte length. The Stage 5 operation-form schema checks on a `state_updates` entry are covered by two single transaction vectors (163-state-op-unknown, 164-state-op-missing-field): per AMB-18 an unknown `op` value is reported as `E_SCHEMA_ENUM_VIOLATION` (a closed-enum violation) and a missing operation-form field as `E_SCHEMA_REQUIRED_FIELD`, the generic Stage 5 schema codes, not the dedicated `E_STATE_OP`. The remaining state codes stay deferred: `E_STATE_UNDECLARED` needs a manifest `state_policy` to resolve the declared `(namespace, key)`; `E_STATE_OP` is reserved for the later state-operation processing phase (applying a schema-valid `set`/`delete` against the store), which the validation-only reference implementations do not yet model, so it is declared but unreached; and the runtime client-side `E_STATE_STORAGE_CAP` and `E_STATE_TRANSMIT_BUDGET`, plus the submit-body `E_STATE_DUPLICATE`, need the submit-flow / storage-modeling vector schema. The escape-sensitive per-value wire boundary (a value whose JSON-escaped wire length exceeds its raw `max_size` and therefore overflows the §09 wire budget even when the Stage 5 envelope check passed) is a property of the deferred `E_STATE_TRANSMIT_BUDGET` runtime path; when the submit-flow tranche lands, that path is where the escaped-vs-raw boundary vectors belong.
- **Historical content** (`E_HISTORICAL_*` including `E_HISTORICAL_NO_PUBLICATION_PROOF`, `W_HISTORICAL_*`): require multi-manifest authorization-history scenarios.

The following conditions are not vector-constructible within the wire-only scope of this corpus:

- **`E_SIG_MALFORMED`**: per §11:173, this diagnostic only applies "in a context where stage-5 wire-side field-syntax validation does not apply". On the wire, signature length and base64url-alphabet violations are reported as `E_SCHEMA_FIELD_SYNTAX` at Stage 5 per §04 and §10 first-failing-stage precedence (exercised by vector 151). There is no wire-side construction that bypasses Stage 5 and reaches the Stage 6 raw-signature-decode path; the diagnostic is reachable only from out-of-band signature decoding (an implementation API surface that the corpus does not exercise).

- **Freshness-unverified mode** (§10 "Clock reliability and the verified-time reference"): the trigger is a client-side property (no reliable current-time reference) that no document can induce. The corpus exercises a wire-to-verdict mapping in which each vector's input is a byte sequence and the verdict is the diagnostic the conforming validation pipeline produces; a condition whose trigger lives entirely outside that mapping cannot be a vector. Conforming clients exercise freshness-unverified mode through their clock-acquisition path, not through any document the corpus could supply.

Vector-schema extensions (transport metadata, image responses, expected-warnings array, multi-manifest histories) are deferred to a future tranche. The current corpus exercises every diagnostic code reachable within the existing schema, except `E_SIG_MALFORMED` (not vector-constructible as documented above).
