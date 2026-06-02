#!/usr/bin/env python3
"""
Entangled v1.0 conformance corpus generator.

Produces a deterministic corpus of test vectors for Entangled v1.0 protocol
implementations. Each vector is a complete signed (or deliberately broken)
document with a documented expected verdict (accept / reject + diagnostic).

Run from the repository root:

    python3 corpus/tools/generate.py

Outputs are written to corpus/keys.json, corpus/corpus.json, and
corpus/vectors/<id>/.

Determinism: Ed25519 keys are derived from fixed 32-byte seeds. Signing under
RFC 8032 is deterministic. The output is reproducible byte-for-byte.

Requirements: Python 3.10+, cryptography>=3.4 (for raw Ed25519).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

# Repository root, relative to this script (corpus/tools/generate.py).
ROOT = Path(__file__).resolve().parent.parent
VECTORS_DIR = ROOT / "vectors"

# BIP-39 English wordlist, bundled at corpus/tools/bip39_english.txt. Used to
# compute the publisher's PIP for the derivation vector. The file is the
# canonical wordlist from the Bitcoin BIPs repository
# (bitcoin/bips: bip-0039/english.txt). Its SHA-256 is recorded in
# corpus/README.md for verification.
BIP39_WORDLIST_PATH = Path(__file__).resolve().parent / "bip39_english.txt"

# ---------------------------------------------------------------------------
# Test key seeds. Fixed for reproducibility. NEVER use these for any real
# deployment; they are public test fixtures.
# ---------------------------------------------------------------------------
PUBLISHER_SEED = b"ENTANGLED-v1.0-publisher-test01\x00"
RUNTIME_SEED = b"ENTANGLED-v1.0-runtime-test0001\x00"
ORIGIN_SEED = b"ENTANGLED-v1.0-origin-test00001\x00"
RUNTIME_SEED_2 = b"ENTANGLED-v1.0-runtime-test0002\x00"
ORIGIN_SEED_2 = b"ENTANGLED-v1.0-origin-test00002\x00"

assert len(PUBLISHER_SEED) == 32
assert len(RUNTIME_SEED) == 32
assert len(ORIGIN_SEED) == 32
assert len(RUNTIME_SEED_2) == 32
assert len(ORIGIN_SEED_2) == 32


# ---------------------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------------------
def b64u(data: bytes) -> str:
    """RFC 4648 §5 base64url, no padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    """Decode base64url with strict padding rules; only used in tooling."""
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


# Order of the Ed25519 base point (RFC 8032). Used to construct non-canonical
# S signatures (S' = S + L) for the strict-profile S-canonicalization test.
ED25519_L = 2**252 + 27742317777372353535851937790883648493

# Prime defining the Ed25519 base field: p = 2^255 - 19 (RFC 8032).
ED25519_P = 2**255 - 19


def non_canonical_s(sig_bytes: bytes) -> bytes:
    """Given a valid 64-byte Ed25519 signature R||S, return R||(S + L).

    Under cofactored verification, the resulting signature still verifies
    because [L]B is the identity. Under the strict profile, S + L >= L is
    non-canonical and rejected. The vector exercises strict-profile S-range
    enforcement.
    """
    assert len(sig_bytes) == 64
    R = sig_bytes[:32]
    S = int.from_bytes(sig_bytes[32:], "little")
    S_prime = S + ED25519_L
    return R + S_prime.to_bytes(32, "little")


def non_canonical_r_encoding() -> bytes:
    """Return a 32-byte non-canonical Ed25519 point encoding.

    The y-coordinate portion (low 255 bits) is 2^255 - 1, which exceeds the
    field prime p = 2^255 - 19. RFC 8032 requires y < p; the strict profile
    rejects encodings with y >= p. The x-sign bit (top bit of byte 31) is
    arbitrary; using 1 here keeps the encoding all-0xff for clarity.
    """
    return bytes([0xFF] * 32)


# Small-order Ed25519 public key: the identity point. Compressed encoding is
# the little-endian byte representation of the y-coordinate, with the high bit
# of the last byte carrying the x-sign. For the identity, y = 1 and x = 0, so
# the encoding is 0x01 followed by 31 zero bytes.
SMALL_ORDER_A = bytes([0x01]) + bytes(31)


def keypair(seed: bytes) -> tuple[Ed25519PrivateKey, bytes]:
    """Derive an Ed25519 keypair from a 32-byte seed. Returns (priv, pub_bytes)."""
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, pub


def jcs(obj) -> bytes:
    """JCS canonicalization (RFC 8785) for the Entangled JSON subset.

    Entangled uses integer-only numbers, no nulls, no duplicate keys, and
    valid UTF-8 strings, so JCS reduces to: sort object keys lex, no
    whitespace, JSON-standard escaping, UTF-8 output.

    NOTE: This helper is sufficient ONLY for the present corpus, which uses
    ASCII-only object keys and integer-only numbers. It is NOT a complete
    RFC 8785 implementation. Before adding vectors that exercise:
      - non-ASCII member names (JCS sorts by UTF-16 code units, not Python's
        default codepoint order - they diverge for characters above U+FFFF);
      - numeric edge cases other than non-negative integers (RFC 8785 §3.2.2.3
        reuses ECMA-262 number serialization, which Python's json does not);
      - object members containing characters that Python's json escapes
        differently from RFC 8785 (forward slash, U+007F, etc.),
    replace this with a verified RFC 8785 implementation, otherwise the
    generated signatures will diverge from the wire-format expectation.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sign(priv: Ed25519PrivateKey, context: str, payload: dict) -> str:
    """Sign an Entangled payload with the given context string.

    signature_input = context_string || 0x00 || JCS(payload)
    Returns the signature as base64url with no padding.
    """
    sig_input = context.encode("ascii") + b"\x00" + jcs(payload)
    sig = priv.sign(sig_input)
    return b64u(sig)


def sha256_b64u(data: bytes) -> str:
    """SHA-256 of `data`, formatted as 'sha-256:<base64url>'."""
    digest = hashlib.sha256(data).digest()
    return f"sha-256:{b64u(digest)}"


def onion_address(origin_pub: bytes) -> str:
    """Tor v3 onion address from a 32-byte Ed25519 public key (rend-spec-v3)."""
    version = bytes([0x03])
    checksum = hashlib.sha3_256(b".onion checksum" + origin_pub + version).digest()[:2]
    body = origin_pub + checksum + version
    return base64.b32encode(body).decode("ascii").lower() + ".onion"


def load_bip39_wordlist() -> list[str] | None:
    """Load the bundled BIP-39 English wordlist, returning None if absent.

    The corpus PIP-derivation vector is populated only when the wordlist file
    is present; absence is non-fatal so the rest of the corpus regenerates.
    """
    if not BIP39_WORDLIST_PATH.exists():
        return None
    words = BIP39_WORDLIST_PATH.read_text(encoding="ascii").splitlines()
    if len(words) != 2048:
        raise RuntimeError(
            f"BIP-39 wordlist at {BIP39_WORDLIST_PATH} has {len(words)} entries; "
            f"expected 2048."
        )
    return words


def compute_pip(pub_key: bytes, wordlist: list[str]) -> str:
    """Derive the 24-word PIP from a 32-byte Ed25519 public key (§05).

    Procedure (BIP-39 over `K_publisher.pub`):
      1. entropy = pub_key (256 bits = 32 bytes).
      2. checksum = first 8 bits of SHA-256(entropy).
      3. bits = entropy || checksum (264 bits).
      4. split into 24 groups of 11 bits, MSB-first.
      5. each group indexes the BIP-39 English wordlist.
      6. join with single ASCII spaces.
    """
    if len(pub_key) != 32:
        raise ValueError("PIP derivation requires a 32-byte Ed25519 public key.")
    if len(wordlist) != 2048:
        raise ValueError("BIP-39 wordlist must contain exactly 2048 entries.")
    checksum_byte = hashlib.sha256(pub_key).digest()[0]
    bits = int.from_bytes(pub_key, "big") << 8 | checksum_byte  # 264 bits total
    words: list[str] = []
    for i in range(24):
        shift = (23 - i) * 11
        idx = (bits >> shift) & 0x7FF
        words.append(wordlist[idx])
    return " ".join(words)


# ---------------------------------------------------------------------------
# Domain separation context strings (§05)
# ---------------------------------------------------------------------------
CTX_MANIFEST = "ENTANGLED-v1 manifest"
CTX_CONTENT = "ENTANGLED-v1 content"
CTX_TRANSACTION = "ENTANGLED-v1 transaction"


# ---------------------------------------------------------------------------
# Document factories
# ---------------------------------------------------------------------------
def make_manifest(*, publisher_priv, publisher_pub, origin_pub, runtime_pub,
                  issued_at="2026-05-07T00:00:00Z",
                  next_expected="2026-06-06T00:00:00Z",
                  updated="2026-05-07T00:00:00Z",
                  state_policy=None,
                  not_after: str | None = None,
                  migration_pointer: dict | None = None) -> dict:
    """Build and sign a minimal valid manifest.

    Optional `not_after`: when provided, added as `origin.not_after` (§06).
    Optional `migration_pointer`: when provided, added as the top-level
    `migration_pointer` field (§06).
    """
    if state_policy is None:
        state_policy = []
    origin: dict = {
        "carrier": "tor-v3",
        "address": onion_address(origin_pub),
        "origin_pubkey": b64u(origin_pub),
    }
    if not_after is not None:
        origin["not_after"] = not_after
    payload: dict = {
        "spec_version": "1.0",
        "kind": "manifest",
        "publisher_pubkey": b64u(publisher_pub),
        "origin": origin,
        "canary": {
            "runtime_pubkey": b64u(runtime_pub),
            "issued_at": issued_at,
            "next_expected": next_expected,
            "statement": "No warrants received.",
        },
        "state_policy": state_policy,
        "navigation": [],
        "min_refresh_interval": 3600,
        "updated": updated,
    }
    if migration_pointer is not None:
        payload["migration_pointer"] = migration_pointer
    payload["sig"] = sign(publisher_priv, CTX_MANIFEST, payload)
    return payload


def make_content(*, runtime_priv, path="/articles/first-post",
                 title="First post", published_at="2026-05-07T00:00:00Z",
                 blocks=None) -> dict:
    """Build and sign a minimal valid content document."""
    if blocks is None:
        blocks = [
            {
                "kind": "paragraph",
                "content": [
                    {"kind": "text", "value": "Hello, world.", "marks": []},
                ],
            }
        ]
    payload = {
        "spec_version": "1.0",
        "kind": "content",
        "path": path,
        "meta": {"title": title, "published_at": published_at},
        "blocks": blocks,
    }
    payload["sig"] = sign(runtime_priv, CTX_CONTENT, payload)
    return payload


def make_transaction(*, runtime_priv, in_response_to="/contact",
                     submit_body=None, blocks=None,
                     state_updates=None,
                     request_id_override: str | None = None) -> tuple[dict, dict]:
    """Build and sign a transaction document.

    Returns (transaction_doc, submit_body_used). The submit body is needed by
    the client to verify request_hash; vectors carrying transactions also
    carry the corresponding submit body.

    When `request_id_override` is set, the transaction document carries that
    `request_id` while the submit body keeps its own (real) `request_id`, so
    `request_hash` still matches the recorded submit body. This isolates a
    `request_id` binding mismatch (E_BIND_REQUEST_ID): the transaction's
    `request_id` is an independent copied field, not part of the hashed submit
    body, so the mismatch does not perturb the request_hash check.
    """
    if submit_body is None:
        submit_body = {
            "fields": {"message": "hello", "name": "alice"},
            "request_state": [],
            "request_id": "AAECAwQFBgcICQoLDA0ODw",
        }
    if blocks is None:
        blocks = [
            {
                "kind": "feedback",
                "variant": "success",
                "content": [
                    {"kind": "text", "value": "Received.", "marks": []},
                ],
            }
        ]
    if state_updates is None:
        state_updates = []
    submit_canonical = jcs(submit_body)
    request_hash = sha256_b64u(submit_canonical)
    tx_request_id = (
        request_id_override
        if request_id_override is not None
        else submit_body["request_id"]
    )
    payload = {
        "spec_version": "1.0",
        "kind": "transaction",
        "in_response_to": in_response_to,
        "request_id": tx_request_id,
        "request_hash": request_hash,
        "state_updates": state_updates,
        "blocks": blocks,
    }
    payload["sig"] = sign(runtime_priv, CTX_TRANSACTION, payload)
    return payload, submit_body


# ---------------------------------------------------------------------------
# Vector emission
# ---------------------------------------------------------------------------
def write_vector(vid: str, body: bytes, *, filename: str = "input.json") -> str:
    """Write a vector's raw bytes to corpus/vectors/<vid>/<filename>.

    Returns the relative path stored in the corpus index.
    """
    vdir = VECTORS_DIR / vid
    vdir.mkdir(parents=True, exist_ok=True)
    path = vdir / filename
    path.write_bytes(body)
    return f"vectors/{vid}/{filename}"


def vec(vid: str, kind: str, description: str, spec_refs: list[str],
        verdict: str, *, body: bytes | None = None,
        body_obj: dict | None = None, diagnostic: str | None = None,
        diagnostic_details: dict | None = None,
        context: dict | None = None,
        extra_files: dict[str, bytes] | None = None) -> dict:
    """Build a corpus vector entry and write its files."""
    if body is None:
        if body_obj is None:
            raise ValueError("either body or body_obj required")
        # Serialize without sort_keys so the wire form preserves authoring order.
        body = json.dumps(body_obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    input_path = write_vector(vid, body)
    expected: dict = {"verdict": verdict}
    if diagnostic is not None:
        expected["diagnostic"] = diagnostic
    if diagnostic_details is not None:
        expected["diagnostic_details"] = diagnostic_details
    entry = {
        "id": vid,
        "kind": kind,
        "description": description,
        "spec_refs": spec_refs,
        "input": input_path,
        "expected": expected,
    }
    if context is not None:
        entry["context"] = context
    if extra_files:
        for fname, fdata in extra_files.items():
            write_vector(vid, fdata, filename=fname)
        entry["extra_files"] = sorted(extra_files.keys())
    return entry


# ---------------------------------------------------------------------------
# Vector definitions
# ---------------------------------------------------------------------------
def positive_vectors(keys) -> list[dict]:
    """Documents that a conforming v1.0 implementation MUST accept."""
    out: list[dict] = []
    pp, pp_pub = keys["publisher_priv"], keys["publisher_pub"]
    rp, rp_pub = keys["runtime_priv"], keys["runtime_pub"]
    op, op_pub = keys["origin_priv"], keys["origin_pub"]

    # 001: minimal valid manifest
    m = make_manifest(
        publisher_priv=pp, publisher_pub=pp_pub,
        origin_pub=op_pub, runtime_pub=rp_pub,
    )
    out.append(vec(
        "001-manifest-valid-minimal",
        kind="manifest",
        description="Minimal valid manifest signed by K_publisher. Empty state_policy and navigation. Tor v3 origin with derived address.",
        spec_refs=["§02", "§05", "§06"],
        verdict="accept",
        body_obj=m,
        context={"fetched_origin_address": m["origin"]["address"]},
    ))

    # 002: valid manifest with state_policy
    m2 = make_manifest(
        publisher_priv=pp, publisher_pub=pp_pub,
        origin_pub=op_pub, runtime_pub=rp_pub,
        state_policy=[
            {
                "namespace": "session",
                "key": "auth",
                "mode": "request",
                "max_size": 512,
                "max_lifetime": 86400,
                "purpose": "Authenticate submit requests after login.",
            },
            {
                "namespace": "ui",
                "key": "lang",
                "mode": "client_only",
                "max_size": 32,
                "max_lifetime": 7776000,
                "purpose": "Remember the chosen language for the user interface.",
            },
        ],
    )
    out.append(vec(
        "002-manifest-valid-state-policy",
        kind="manifest",
        description="Valid manifest declaring two state_policy entries: one request-mode session token, one client-only language preference.",
        spec_refs=["§06", "§07"],
        verdict="accept",
        body_obj=m2,
        context={"fetched_origin_address": m2["origin"]["address"]},
    ))

    # 003: valid content document
    c = make_content(runtime_priv=rp)
    out.append(vec(
        "003-content-valid-minimal",
        kind="content",
        description="Minimal valid content document with a single paragraph block. Signed by K_runtime authorized by manifest 001.",
        spec_refs=["§02", "§03", "§05"],
        verdict="accept",
        body_obj=c,
        context={
            "fetched_path": c["path"],
            "expected_runtime_pubkey": b64u(rp_pub),
        },
    ))

    # 004: valid content with multiple block kinds
    c2 = make_content(
        runtime_priv=rp,
        path="/articles/blocks-showcase",
        title="Block showcase",
        blocks=[
            {"kind": "heading", "level": 1, "content": [
                {"kind": "text", "value": "Showcase", "marks": []},
            ]},
            {"kind": "paragraph", "content": [
                {"kind": "text", "value": "An example of ", "marks": []},
                {"kind": "text", "value": "bold", "marks": ["bold"]},
                {"kind": "text", "value": " and ", "marks": []},
                {"kind": "text", "value": "italic", "marks": ["italic"]},
                {"kind": "text", "value": " text.", "marks": []},
            ]},
            {"kind": "list", "ordered": False, "items": [
                [{"kind": "text", "value": "First", "marks": []}],
                [{"kind": "text", "value": "Second", "marks": []}],
            ]},
            {"kind": "code_block", "language": "rust",
             "content": "fn main() {\n    println!(\"hi\");\n}"},
            {"kind": "divider"},
            {"kind": "quote", "content": [
                {"kind": "text", "value": "Lorem ipsum.", "marks": []},
            ]},
        ],
    )
    out.append(vec(
        "004-content-valid-blocks-showcase",
        kind="content",
        description="Valid content document exercising heading, marked paragraph, unordered list, code_block, divider, and quote. No image; image is exercised separately.",
        spec_refs=["§03"],
        verdict="accept",
        body_obj=c2,
        context={
            "fetched_path": c2["path"],
            "expected_runtime_pubkey": b64u(rp_pub),
        },
    ))

    # 005: valid transaction document
    t, sb = make_transaction(runtime_priv=rp)
    out.append(vec(
        "005-transaction-valid-minimal",
        kind="transaction",
        description="Minimal valid transaction document with a single feedback block. Carries a request_hash bound to the submit body in extra_files/submit_body.json.",
        spec_refs=["§02", "§09"],
        verdict="accept",
        body_obj=t,
        context={
            "submit_path": t["in_response_to"],
            "expected_runtime_pubkey": b64u(rp_pub),
            "submit_body_path": "vectors/005-transaction-valid-minimal/submit_body.json",
        },
        extra_files={
            "submit_body.json": json.dumps(
                sb, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8"),
        },
    ))

    # 006: valid manifest with origin.not_after declared
    m6 = make_manifest(
        publisher_priv=pp, publisher_pub=pp_pub,
        origin_pub=op_pub, runtime_pub=rp_pub,
        not_after="2027-05-07T00:00:00Z",
    )
    out.append(vec(
        "006-manifest-valid-not-after",
        kind="manifest",
        description=(
            "Valid manifest declaring origin.not_after = 2027-05-07T00:00:00Z, one year "
            "after canary.issued_at and well within the 5-year ceiling. At clock_now "
            "(2026-05-07) the manifest is not yet origin-expired. Exercises the rc.14 "
            "origin-not-after schema acceptance and Stage 5 cross-field semantic checks "
            "(strictly later than canary.issued_at; not more than 5 years after; SHOULD "
            "later than canary.next_expected - satisfied here)."
        ),
        spec_refs=["§06", "§10"],
        verdict="accept",
        body_obj=m6,
        context={"fetched_origin_address": m6["origin"]["address"]},
    ))

    # 007: valid content document whose seq is above 2^53.
    #
    # §04 (rc.27): Entangled integers up to 2^63-1 are canonicalized as exact
    # decimal across the whole range, overriding the IEEE 754 binary64
    # interpretation for integers above 2^53. seq = 9007199254740993 (2^53+1)
    # is the smallest integer with no binary64 representation; an
    # implementation that routed it through a double would emit
    # 9007199254740992 and produce different canonical bytes (and a failing
    # signature). The signature here is computed over the exact-decimal
    # canonical form, so a conforming verifier MUST accept it and a
    # binary64-rounding one MUST fail. Exercises the §04 integer
    # serialization rule at the supra-2^53 boundary.
    big_seq = 9007199254740993  # 2**53 + 1
    c7 = {
        "spec_version": "1.0",
        "kind": "content",
        "path": "/articles/large-seq",
        "seq": big_seq,
        "meta": {"title": "Large seq", "published_at": "2026-05-07T00:00:00Z"},
        "blocks": [
            {
                "kind": "paragraph",
                "content": [
                    {"kind": "text", "value": "Hello, world.", "marks": []},
                ],
            }
        ],
    }
    c7["sig"] = sign(rp, CTX_CONTENT, c7)
    out.append(vec(
        "007-content-valid-large-seq",
        kind="content",
        description=(
            "Valid content document whose seq = 9007199254740993 (2^53 + 1), "
            "the smallest integer with no IEEE 754 binary64 representation. "
            "Per §04 integer serialization, Entangled integers up to 2^63-1 "
            "are canonicalized as exact decimal across the whole range, "
            "overriding the binary64 interpretation above 2^53. The K_runtime "
            "signature is computed over the exact-decimal canonical form. A "
            "conforming verifier MUST accept; an implementation that routes "
            "the seq through a binary64 double serializes 9007199254740992 "
            "and fails signature verification. Signed by K_runtime authorized "
            "by manifest 001."
        ),
        spec_refs=["§02", "§04", "§05"],
        verdict="accept",
        body_obj=c7,
        context={
            "fetched_path": c7["path"],
            "expected_runtime_pubkey": b64u(rp_pub),
        },
    ))

    return out


def negative_vectors(keys) -> list[dict]:
    """Documents that a conforming v1.0 implementation MUST reject, with the
    specific diagnostic listed."""
    out: list[dict] = []
    pp, pp_pub = keys["publisher_priv"], keys["publisher_pub"]
    rp, rp_pub = keys["runtime_priv"], keys["runtime_pub"]
    op, op_pub = keys["origin_priv"], keys["origin_pub"]

    # ---- input: BOM, bad UTF-8 ----
    m = make_manifest(
        publisher_priv=pp, publisher_pub=pp_pub,
        origin_pub=op_pub, runtime_pub=rp_pub,
    )
    m_bytes = json.dumps(m, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    out.append(vec(
        "100-input-bom",
        kind="manifest",
        description="Otherwise-valid manifest preceded by a UTF-8 BOM (EF BB BF). Must be rejected at stage 2 input checks.",
        spec_refs=["§04"],
        verdict="reject",
        diagnostic="E_INPUT_BOM",
        body=b"\xEF\xBB\xBF" + m_bytes,
    ))
    out.append(vec(
        "101-input-bad-utf8",
        kind="manifest",
        description="Body is not valid UTF-8: contains a lone 0xFE byte that is not part of any UTF-8 sequence. Must be rejected at stage 2.",
        spec_refs=["§04"],
        verdict="reject",
        diagnostic="E_INPUT_UTF8",
        body=b'{"spec_version":"1.0","kind":"manifest","x":"\xFE"}',
    ))

    # ---- parse: duplicate keys ----
    out.append(vec(
        "110-parse-duplicate-keys",
        kind="content",
        description="Content document with a duplicate top-level member name (\"path\" appears twice). Must be rejected at stage 3 with E_PARSE_DUPLICATE_KEY before schema validation.",
        spec_refs=["§04"],
        verdict="reject",
        diagnostic="E_PARSE_DUPLICATE_KEY",
        body=b'{"spec_version":"1.0","kind":"content","path":"/x","path":"/y","meta":{"title":"t","published_at":"2026-05-07T00:00:00Z"},"blocks":[{"kind":"divider"}],"sig":"' + (b"A" * 86) + b'"}',
    ))

    # ---- kind / spec_version ----
    out.append(vec(
        "120-spec-version-wrong",
        kind="manifest",
        description="Document declaring spec_version \"1.1\". A v1.0 client must reject with E_KIND_SPEC_VERSION before schema validation.",
        spec_refs=["§02", "§11"],
        verdict="reject",
        diagnostic="E_KIND_SPEC_VERSION",
        body=b'{"spec_version":"1.1","kind":"manifest","sig":"' + (b"A" * 86) + b'"}',
    ))
    out.append(vec(
        "121-kind-unknown",
        kind="manifest",
        description="Document whose kind is \"unknown\" (not one of manifest/content/transaction). Rejected at stage 4 with E_KIND_UNKNOWN.",
        spec_refs=["§02", "§11"],
        verdict="reject",
        diagnostic="E_KIND_UNKNOWN",
        body=b'{"spec_version":"1.0","kind":"unknown","sig":"' + (b"A" * 86) + b'"}',
    ))

    # ---- schema: unknown field, missing required, null value ----
    bad = dict(m)
    bad["unexpected_field"] = "x"
    # need to re-sign would be wrong (signature wouldn't match this payload anyway,
    # because we can't sign a document our schema rejects from inside the
    # generator). Use the original signature; the test exercises stage 5 schema
    # rejection ahead of stage 6 signature verification.
    out.append(vec(
        "130-schema-unknown-field",
        kind="manifest",
        description="Manifest with an extra top-level field \"unexpected_field\". Closed-schema discipline rejects at stage 5 with E_SCHEMA_UNKNOWN_FIELD before signature verification.",
        spec_refs=["§02", "§06"],
        verdict="reject",
        diagnostic="E_SCHEMA_UNKNOWN_FIELD",
        body_obj=bad,
    ))

    bad2 = {k: v for k, v in m.items() if k != "min_refresh_interval"}
    out.append(vec(
        "131-schema-missing-required",
        kind="manifest",
        description="Manifest with required field min_refresh_interval omitted. Rejected at stage 5 with E_SCHEMA_REQUIRED_FIELD.",
        spec_refs=["§06"],
        verdict="reject",
        diagnostic="E_SCHEMA_REQUIRED_FIELD",
        body_obj=bad2,
    ))

    m_null_nav = dict(m)
    m_null_nav["navigation"] = None
    m_null_nav["sig"] = "A" * 86  # placeholder; stage 5 fails before stage 6
    out.append(vec(
        "132-schema-null-value",
        kind="manifest",
        description=(
            "Manifest where navigation is null. All other required fields "
            "are present and well-formed; only the null literal triggers "
            "stage 5 rejection. E_SCHEMA_NULL_VALUE."
        ),
        spec_refs=["§04", "§06"],
        verdict="reject",
        diagnostic="E_SCHEMA_NULL_VALUE",
        body_obj=m_null_nav,
        context={"fetched_origin_address": m_null_nav["origin"]["address"]},
    ))

    # Invalid block kind in content document
    c_bad_block = make_content(
        runtime_priv=rp,
        path="/articles/bad-block",
        title="Bad block",
        blocks=[{"kind": "marquee", "content": "scrolling text"}],
    )
    out.append(vec(
        "133-schema-block-kind-unknown",
        kind="content",
        description=(
            "Content document with a block whose kind is \"marquee\", a "
            "syntactically valid slug not in the enumerated block kinds "
            "(§03). Stage 5 schema rejection. E_SCHEMA_ENUM_VIOLATION."
        ),
        spec_refs=["§03", "§11"],
        verdict="reject",
        diagnostic="E_SCHEMA_ENUM_VIOLATION",
        body_obj=c_bad_block,
        context={
            "fetched_path": c_bad_block["path"],
            "expected_runtime_pubkey": b64u(rp_pub),
        },
    ))

    # ---- numeric grammar: float, big int ----
    out.append(vec(
        "140-numeric-float",
        kind="manifest",
        description="Manifest where min_refresh_interval has a float-shape token (3600.0). The strict integer grammar rejects floats lexically. E_SCHEMA_NON_INTEGER.",
        spec_refs=["§04"],
        verdict="reject",
        diagnostic="E_SCHEMA_NON_INTEGER",
        body=b'{"spec_version":"1.0","kind":"manifest","min_refresh_interval":3600.0,"sig":"' + (b"A" * 86) + b'"}',
    ))
    out.append(vec(
        "141-numeric-exponent",
        kind="manifest",
        description="Manifest where min_refresh_interval is written in exponent form (3.6e3). Integer grammar rejects exponents. E_SCHEMA_NON_INTEGER.",
        spec_refs=["§04"],
        verdict="reject",
        diagnostic="E_SCHEMA_NON_INTEGER",
        body=b'{"spec_version":"1.0","kind":"manifest","min_refresh_interval":3.6e3,"sig":"' + (b"A" * 86) + b'"}',
    ))
    m_overflow = dict(m)
    m_overflow["min_refresh_interval"] = 9223372036854775808  # 2**63
    m_overflow["sig"] = "A" * 86
    out.append(vec(
        "142-numeric-overflow",
        kind="manifest",
        description=(
            "Manifest where min_refresh_interval is 9223372036854775808 "
            "(= 2^63), one above the protocol's 64-bit signed integer "
            "cap. All other required fields are present and well-formed. "
            "E_SCHEMA_NON_INTEGER."
        ),
        spec_refs=["§04", "§06"],
        verdict="reject",
        diagnostic="E_SCHEMA_NON_INTEGER",
        body_obj=m_overflow,
        context={"fetched_origin_address": m_overflow["origin"]["address"]},
    ))

    # ---- 143-submit-budget-state-overflow (Stage 5, E_SUBMIT_BUDGET) ----
    # Manifest whose state_policy declares 32 request-mode entries each
    # with max_size = 2048 bytes. The aggregate worst-case encoded wire
    # contribution to the submit body's request_state array counts the
    # value at its raw max_size (2048 UTF-8 bytes, no JSON-escape
    # expansion, per §07 max_size as a raw UTF-8 byte length): per entry
    # 36 envelope bytes + 2 namespace bytes + 3 key bytes + 2048 value
    # bytes = 2089 bytes, times 32 entries, plus 31 inter-entry commas =
    # 66879 bytes, well above the state_budget of 53248 bytes defined in
    # §09 ("Submit body budget partition"). Per §07 "Submit budget
    # satisfiability", the manifest is rejected at Stage 5 schema
    # validation as E_SUBMIT_BUDGET with details.component = "state". The
    # manifest is signed correctly and otherwise valid; the
    # satisfiability violation is the only live violation at Stage 5.
    # The escape-sensitive per-value wire boundary (a value whose
    # JSON-escaped wire length exceeds its raw max_size) lives in the
    # deferred runtime E_STATE_TRANSMIT_BUDGET path, not in this Stage 5
    # envelope check; see corpus/README.md.
    state_policy_overflow = [
        {
            "namespace": "ns",
            "key": f"k{i:02d}",
            "mode": "request",
            "max_size": 2048,
            "max_lifetime": 86400,
            "purpose": "Aggregate overflow probe.",
        }
        for i in range(32)
    ]
    m_143 = make_manifest(
        publisher_priv=pp, publisher_pub=pp_pub,
        origin_pub=op_pub, runtime_pub=rp_pub,
        state_policy=state_policy_overflow,
    )
    out.append(vec(
        "143-submit-budget-state-overflow",
        kind="manifest",
        description=(
            "Manifest whose state_policy declares 32 request-mode "
            "entries each with max_size = 2048 bytes. Aggregate "
            "worst-case encoded wire contribution to request_state is "
            "66879 bytes (32 entries * (2048 raw value bytes + 41 "
            "envelope bytes: 36 fixed + 2 namespace + 3 key) + 31 "
            "commas), exceeding the state_budget of 53248 bytes defined "
            "in §09 ('Submit body budget partition') by 13631 bytes. The "
            "value is counted at its raw max_size (UTF-8 byte length, no "
            "JSON-escape expansion) per §07 max_size. Per §07 'Submit "
            "budget satisfiability', rejected at Stage 5 schema "
            "validation as E_SUBMIT_BUDGET with details.component = "
            "'state'. Manifest is signed correctly; the satisfiability "
            "violation is the only live Stage 5 violation."
        ),
        spec_refs=["§07", "§09", "§11"],
        verdict="reject",
        diagnostic="E_SUBMIT_BUDGET",
        diagnostic_details={
            "component": "state",
            "declared_bytes": 66879,
            "budget_bytes": 53248,
        },
        body_obj=m_143,
        context={"fetched_origin_address": m_143["origin"]["address"]},
    ))

    # ---- 144-schema-carrier-enum-violation (Stage 5, E_SCHEMA_ENUM_VIOLATION) ----
    #
    # AMB-10: origin.carrier is a closed value set whose only v1.0 member is
    # "tor-v3". A syntactically valid string outside the set ("i2p") is an
    # enumerated-set violation, not a string-syntax violation: rejected at
    # Stage 5 as E_SCHEMA_ENUM_VIOLATION (§06, §11), the same code used for
    # an unknown state-policy mode or feedback variant. The manifest is
    # otherwise valid and re-signed over the mutated payload, so the
    # signature verifies and the enum violation is the only live Stage 5
    # violation.
    m_carrier = make_manifest(
        publisher_priv=pp, publisher_pub=pp_pub,
        origin_pub=op_pub, runtime_pub=rp_pub,
    )
    del m_carrier["sig"]
    m_carrier["origin"]["carrier"] = "i2p"
    m_carrier["sig"] = sign(pp, CTX_MANIFEST, m_carrier)
    out.append(vec(
        "144-schema-carrier-enum-violation",
        kind="manifest",
        description=(
            "Manifest whose origin.carrier is the syntactically valid string "
            "\"i2p\", outside the closed v1.0 value set {tor-v3}. Per §06 and "
            "§11 this is an enumerated-set violation rejected at Stage 5 as "
            "E_SCHEMA_ENUM_VIOLATION (the same code as an unknown state-policy "
            "mode or feedback variant), not E_SCHEMA_FIELD_SYNTAX. The "
            "manifest is re-signed over the mutated payload so the signature "
            "verifies; the carrier enum violation is the only live Stage 5 "
            "violation."
        ),
        spec_refs=["§06", "§11"],
        verdict="reject",
        diagnostic="E_SCHEMA_ENUM_VIOLATION",
        body_obj=m_carrier,
        context={"fetched_origin_address": m_carrier["origin"]["address"]},
    ))

    # ---- 145-schema-address-uppercase-syntax (Stage 5, E_SCHEMA_FIELD_SYNTAX) ----
    #
    # AMB-11: the lowercase-base32, 56-character, .onion-suffixed shape of
    # origin.address is a declared field syntax (§06). A value that uses
    # uppercase base32 letters deviates from the canonical wire form and is
    # rejected at Stage 5 as E_SCHEMA_FIELD_SYNTAX, before signature
    # verification and before the §05 Stage 9 binding (which covers only key
    # derivation and the fetched-vs-declared comparison on an already-
    # canonical address). The address body is upper-cased; the manifest is
    # re-signed so the signature itself verifies and the field-syntax
    # violation is the only live Stage 5 violation.
    m_addr = make_manifest(
        publisher_priv=pp, publisher_pub=pp_pub,
        origin_pub=op_pub, runtime_pub=rp_pub,
    )
    del m_addr["sig"]
    canonical_addr = m_addr["origin"]["address"]
    body, suffix = canonical_addr[:-len(".onion")], ".onion"
    m_addr["origin"]["address"] = body.upper() + suffix
    m_addr["sig"] = sign(pp, CTX_MANIFEST, m_addr)
    out.append(vec(
        "145-schema-address-uppercase-syntax",
        kind="manifest",
        description=(
            "Manifest whose origin.address uses uppercase base32 letters in "
            "the 56-character body (otherwise the canonical onion address). "
            "Per §06 the lowercase-base32 shape is a declared field syntax; a "
            "non-canonical literal is rejected at Stage 5 as "
            "E_SCHEMA_FIELD_SYNTAX, before signature verification and before "
            "the §05 Stage 9 binding. The manifest is re-signed over the "
            "mutated payload so the signature verifies; the field-syntax "
            "violation is the only live Stage 5 violation. Distinct from "
            "vector 175 (E_BIND_ORIGIN), which exercises a genuine "
            "key-derivation mismatch with both addresses lowercase."
        ),
        spec_refs=["§05", "§06", "§11"],
        verdict="reject",
        diagnostic="E_SCHEMA_FIELD_SYNTAX",
        body_obj=m_addr,
        context={"fetched_origin_address": canonical_addr},
    ))

    # ---- 146-schema-empty-array (Stage 5, E_SCHEMA_REQUIRED_FIELD; AMB-13) ----
    #
    # A mandatory array that is present but empty. §02:186 requires content
    # `blocks` to contain at least one block; an empty `blocks: []` does not
    # meet the minimum element count. Per AMB-13 (rc.31) this is
    # E_SCHEMA_REQUIRED_FIELD (the required element is absent), not
    # E_SCHEMA_FIELD_LENGTH (which is for exceeding a maximum). The document
    # is signed correctly over the empty-blocks payload so the signature
    # verifies and the empty-array violation is the only live Stage 5
    # violation.
    c_empty = make_content(runtime_priv=rp, path="/articles/empty", blocks=[])
    out.append(vec(
        "146-schema-empty-array",
        kind="content",
        description=(
            "Content document whose mandatory `blocks` array is present but "
            "empty. §02:186 requires at least one block; per AMB-13 an empty "
            "mandatory array is E_SCHEMA_REQUIRED_FIELD (the required element "
            "is absent), not E_SCHEMA_FIELD_LENGTH. Signed correctly so the "
            "empty-array violation is the only live Stage 5 violation."
        ),
        spec_refs=["§02", "§03", "§11"],
        verdict="reject",
        diagnostic="E_SCHEMA_REQUIRED_FIELD",
        body_obj=c_empty,
        context={
            "fetched_path": c_empty["path"],
            "expected_runtime_pubkey": b64u(rp_pub),
        },
    ))

    # ---- 147-schema-nested-link (Stage 5, E_SCHEMA_BLOCK_NOT_PERMITTED;
    #      AMB-14) ----
    #
    # A `link` block whose `label` inline array contains an inline `link`
    # element. §03:654 forbids nested links in a link label. Per AMB-14
    # (rc.31) the violation is an inline element of an enumerated kind
    # appearing where that kind is not permitted: E_SCHEMA_BLOCK_NOT_PERMITTED,
    # not E_SCHEMA_ENUM_VIOLATION. Signed correctly so the nested-link
    # violation is the only live Stage 5 violation.
    c_nested = make_content(
        runtime_priv=rp, path="/articles/nested-link",
        blocks=[{
            "kind": "link",
            "label": [
                {"kind": "text", "value": "see ", "marks": []},
                {
                    "kind": "link",
                    "value": "here",
                    "marks": [],
                    "target": {"kind": "same_site", "path": "/articles/foo"},
                },
            ],
            "target": {"kind": "same_site", "path": "/articles/bar"},
        }],
    )
    out.append(vec(
        "147-schema-nested-link",
        kind="content",
        description=(
            "Content document with a `link` block whose `label` contains an "
            "inline `link` element. §03:654 forbids nested links in a link "
            "label; per AMB-14 this is E_SCHEMA_BLOCK_NOT_PERMITTED (an "
            "inline element kind appearing where it is not permitted), not "
            "E_SCHEMA_ENUM_VIOLATION. Signed correctly so the nested-link "
            "violation is the only live Stage 5 violation."
        ),
        spec_refs=["§03", "§11"],
        verdict="reject",
        diagnostic="E_SCHEMA_BLOCK_NOT_PERMITTED",
        body_obj=c_nested,
        context={
            "fetched_path": c_nested["path"],
            "expected_runtime_pubkey": b64u(rp_pub),
        },
    ))

    # ---- 148/149: transaction state_updates hard-range checks ----
    # A transaction "set" state update is validated standalone at Stage 5
    # (no manifest policy needed): a value over the 4096-byte hard ceiling is
    # E_STATE_VALUE_SIZE (§11:286, §07:170), and a ttl outside the 300..7776000
    # hard range is E_STATE_TTL (§11:287, §07:279). The dedicated state codes
    # apply, not the generic E_SCHEMA_FIELD_LENGTH / E_SCHEMA_FIELD_RANGE.
    t_state_value, _ = make_transaction(
        runtime_priv=rp,
        state_updates=[{
            "op": "set",
            "namespace": "session",
            "key": "data",
            "value": "x" * 4097,
            "ttl": 86400,
        }],
    )
    out.append(vec(
        "148-state-value-size",
        kind="transaction",
        description="Transaction whose state_updates set operation carries a value of 4097 raw UTF-8 bytes, one over the 4096-byte protocol hard ceiling (§07). The state_updates array is validated standalone at Stage 5; rejected with E_STATE_VALUE_SIZE (§11:286), the dedicated state code, not the generic E_SCHEMA_FIELD_LENGTH. Signed by K_runtime; namespace, key, and ttl are valid, so the oversized value is the only live violation.",
        spec_refs=["§07", "§11"],
        verdict="reject",
        diagnostic="E_STATE_VALUE_SIZE",
        body_obj=t_state_value,
        context={"expected_runtime_pubkey": b64u(rp_pub)},
    ))

    t_state_ttl, _ = make_transaction(
        runtime_priv=rp,
        state_updates=[{
            "op": "set",
            "namespace": "session",
            "key": "data",
            "value": "ok",
            "ttl": 7776001,
        }],
    )
    out.append(vec(
        "149-state-ttl",
        kind="transaction",
        description="Transaction whose state_updates set operation carries a ttl of 7776001 seconds, one over the 7776000-second (90-day) hard upper bound (§07:279). The state_updates array is validated standalone at Stage 5; rejected with E_STATE_TTL (§11:287), the dedicated state code, not the generic E_SCHEMA_FIELD_RANGE. Signed by K_runtime; value, namespace, and key are valid, so the out-of-range ttl is the only live violation.",
        spec_refs=["§07", "§11"],
        verdict="reject",
        diagnostic="E_STATE_TTL",
        body_obj=t_state_ttl,
        context={"expected_runtime_pubkey": b64u(rp_pub)},
    ))

    # ---- 163/164: transaction state_updates operation-form schema (AMB-18) --
    # A state_updates entry whose `op` is unknown, or whose operation form is
    # missing a required field, is a Stage 5 closed-schema rejection. Per the
    # §07 state-update failure taxonomy and §11, an unknown `op` is a closed-enum
    # violation reported as E_SCHEMA_ENUM_VIOLATION, and a missing
    # operation-form field is reported as E_SCHEMA_REQUIRED_FIELD. The dedicated
    # E_STATE_OP code is reserved for the later state-operation processing phase
    # (applying a set/delete against the store), not the Stage 5 schema check.
    # As in 148/149 the state_updates array is validated standalone at Stage 5
    # (no manifest state_policy needed); each vector keeps a single live
    # violation. Signed by K_runtime.
    t_state_op_unknown, _ = make_transaction(
        runtime_priv=rp,
        state_updates=[{
            "op": "replace",
            "namespace": "session",
            "key": "data",
            "value": "ok",
            "ttl": 86400,
        }],
    )
    out.append(vec(
        "163-state-op-unknown",
        kind="transaction",
        description="Transaction whose state_updates entry carries op=\"replace\", a value outside the closed v1 operation set {set, delete}. Per the §07 state-update failure taxonomy and §11, an unknown op is a closed-enum violation rejected at Stage 5 as E_SCHEMA_ENUM_VIOLATION, not the dedicated E_STATE_OP (reserved for the later state-operation processing phase). The state_updates array is validated standalone at Stage 5; namespace, key, value, and ttl are otherwise valid, so the unknown op is the only live violation. Signed by K_runtime.",
        spec_refs=["§07", "§11"],
        verdict="reject",
        diagnostic="E_SCHEMA_ENUM_VIOLATION",
        body_obj=t_state_op_unknown,
        context={"expected_runtime_pubkey": b64u(rp_pub)},
    ))

    t_state_op_missing, _ = make_transaction(
        runtime_priv=rp,
        state_updates=[{
            "op": "set",
            "namespace": "session",
            "key": "data",
            "value": "ok",
        }],
    )
    out.append(vec(
        "164-state-op-missing-field",
        kind="transaction",
        description="Transaction whose state_updates set operation omits the required ttl field (a set has exactly five fields: op, namespace, key, value, ttl). Per the §07 state-update failure taxonomy and §11, a missing operation-form field is rejected at Stage 5 as E_SCHEMA_REQUIRED_FIELD, not the dedicated E_STATE_OP (reserved for the later state-operation processing phase). The state_updates array is validated standalone at Stage 5; op, namespace, key, and value are otherwise valid, so the absent ttl is the only live violation. Signed by K_runtime.",
        spec_refs=["§07", "§11"],
        verdict="reject",
        diagnostic="E_SCHEMA_REQUIRED_FIELD",
        body_obj=t_state_op_missing,
        context={"expected_runtime_pubkey": b64u(rp_pub)},
    ))

    # ---- 169-state-ttl-over-u32 (Stage 5, E_STATE_TTL; AMB-27) ----
    # A set ttl that is a conforming 64-bit integer above u32::MAX but far
    # outside the 300..7776000 hard range. Per §11:289 an out-of-bounds set ttl
    # is the dedicated E_STATE_TTL regardless of the value's magnitude; it must
    # not collapse to a generic integer-width range code (E_SCHEMA_FIELD_RANGE)
    # because the value happens to exceed a particular implementation's integer
    # width. Pairs with 149 (ttl 7776001, within u32; same code).
    t_state_ttl_over_u32, _ = make_transaction(
        runtime_priv=rp,
        state_updates=[{
            "op": "set",
            "namespace": "session",
            "key": "data",
            "value": "x",
            "ttl": 5000000000,
        }],
    )
    out.append(vec(
        "169-state-ttl-over-u32",
        kind="transaction",
        description="Transaction whose state_updates set operation carries a ttl of 5000000000, a conforming 64-bit integer above u32::MAX but far outside the 300..7776000 hard range (§07:279). Per §11:289 an out-of-bounds set ttl is the dedicated E_STATE_TTL, regardless of the value's magnitude; it must not be reported as a generic integer-width range code (E_SCHEMA_FIELD_RANGE). The state_updates array is validated standalone at Stage 5; value, namespace, and key are valid, so the out-of-range ttl is the only live violation. Signed by K_runtime. Pairs with 149 (ttl 7776001, within u32; same code).",
        spec_refs=["§07", "§11"],
        verdict="reject",
        diagnostic="E_STATE_TTL",
        body_obj=t_state_ttl_over_u32,
        context={"expected_runtime_pubkey": b64u(rp_pub)},
    ))

    # ---- signature: modified payload, wrong length ----
    m_tamper = dict(m)
    # Modify a non-sig field after signing. The signature no longer matches.
    m_tamper["min_refresh_interval"] = m["min_refresh_interval"] + 1
    out.append(vec(
        "150-sig-modified-payload",
        kind="manifest",
        description="Otherwise-valid manifest whose min_refresh_interval was changed after signing. The wire signature no longer verifies. E_SIG_VERIFICATION.",
        spec_refs=["§05"],
        verdict="reject",
        diagnostic="E_SIG_VERIFICATION",
        body_obj=m_tamper,
        context={"fetched_origin_address": m_tamper["origin"]["address"]},
    ))

    # Sig field length: 43 chars instead of the canonical 86. Stage 5 §04
    # declared-length check fires before stage 6 signature decoding (§10
    # first-failing-stage rule), so the diagnostic is E_SCHEMA_FIELD_SYNTAX,
    # not E_SIG_MALFORMED.
    short_sig = b64u(b"\x00" * 32)  # 43 chars
    m_short = dict(m)
    m_short["sig"] = short_sig
    out.append(vec(
        "151-sig-syntax-length",
        kind="manifest",
        description=(
            "Manifest whose sig field is 43 ASCII characters instead of the "
            "canonical 86. §04 declared-length check at stage 5 rejects with "
            "E_SCHEMA_FIELD_SYNTAX before stage 6 signature decoding fires "
            "(§10 first-failing-stage precedence)."
        ),
        spec_refs=["§04", "§02"],
        verdict="reject",
        diagnostic="E_SCHEMA_FIELD_SYNTAX",
        body_obj=m_short,
        context={"fetched_origin_address": m_short["origin"]["address"]},
    ))

    # Non-canonical S: take the valid signature from manifest m, replace S
    # with S + L. The resulting signature verifies under cofactored rules but
    # is rejected under the strict profile (§05).
    real_sig = b64u_decode(m["sig"])
    nc_sig = non_canonical_s(real_sig)
    m_nc = dict(m)
    m_nc["sig"] = b64u(nc_sig)
    out.append(vec(
        "152-sig-non-canonical-s",
        kind="manifest",
        description="Manifest with a signature whose S component is non-canonical (S' = S + L >= L). The signature would verify under cofactored Ed25519, but the strict profile (§05) rejects non-canonical S. E_SIG_VERIFICATION.",
        spec_refs=["§05"],
        verdict="reject",
        diagnostic="E_SIG_VERIFICATION",
        body_obj=m_nc,
        context={"fetched_origin_address": m_nc["origin"]["address"]},
    ))

    # Small-order public key (identity). The strict profile rejects the
    # public key before signature verification; the vector replaces both
    # publisher_pubkey and the sig with a placeholder. Even with a forged
    # signature, the public-key rejection takes precedence.
    m_smallorder = dict(m)
    m_smallorder["publisher_pubkey"] = b64u(SMALL_ORDER_A)
    m_smallorder["sig"] = b64u(b"\x00" * 64)
    out.append(vec(
        "153-sig-small-order-pubkey",
        kind="manifest",
        description="Manifest where publisher_pubkey is the encoded identity point (small-order, order 1). The strict profile (§05) rejects small-order public keys before signature verification; E_SIG_VERIFICATION.",
        spec_refs=["§05"],
        verdict="reject",
        diagnostic="E_SIG_VERIFICATION",
        body_obj=m_smallorder,
        context={"fetched_origin_address": m_smallorder["origin"]["address"]},
    ))

    # ---- base64url strictness ----
    # padded sig
    m_padded = dict(m)
    real_sig_b = b64u_decode(m["sig"])
    m_padded["sig"] = base64.urlsafe_b64encode(real_sig_b).decode("ascii")  # keeps "=" padding - no rstrip
    out.append(vec(
        "160-base64url-padded",
        kind="manifest",
        description="Manifest whose sig field carries '=' padding. Strict base64url decoding rejects with E_SCHEMA_FIELD_SYNTAX before signature verification.",
        spec_refs=["§04", "§02"],
        verdict="reject",
        diagnostic="E_SCHEMA_FIELD_SYNTAX",
        body_obj=m_padded,
        context={"fetched_origin_address": m_padded["origin"]["address"]},
    ))

    # standard alphabet (+/) instead of url-safe (-_)
    m_stdalpha = dict(m)
    std_b64 = base64.b64encode(real_sig_b).rstrip(b"=").decode("ascii")
    if "+" not in std_b64 and "/" not in std_b64:
        # extremely unlikely with random 64-byte sig but handle gracefully
        std_b64 = std_b64[:-1] + "+"
    m_stdalpha["sig"] = std_b64
    out.append(vec(
        "161-base64url-standard-alphabet",
        kind="manifest",
        description="Manifest whose sig field uses the standard base64 alphabet (+ and /) instead of the URL-safe alphabet (- and _). Rejected with E_SCHEMA_FIELD_SYNTAX.",
        spec_refs=["§04"],
        verdict="reject",
        diagnostic="E_SCHEMA_FIELD_SYNTAX",
        body_obj=m_stdalpha,
        context={"fetched_origin_address": m_stdalpha["origin"]["address"]},
    ))

    # whitespace in sig
    m_ws = dict(m)
    m_ws["sig"] = m["sig"][:43] + " " + m["sig"][43:]
    out.append(vec(
        "162-base64url-whitespace",
        kind="manifest",
        description="Manifest whose sig field contains an embedded space character. Strict base64url rejects whitespace; E_SCHEMA_FIELD_SYNTAX.",
        spec_refs=["§04"],
        verdict="reject",
        diagnostic="E_SCHEMA_FIELD_SYNTAX",
        body_obj=m_ws,
        context={"fetched_origin_address": m_ws["origin"]["address"]},
    ))

    # ---- binding: path mismatch, /manifest.json reservation, request_hash ----
    c = make_content(runtime_priv=rp, path="/articles/foo")
    out.append(vec(
        "170-bind-path-mismatch",
        kind="content",
        description="Otherwise-valid content document whose path field is /articles/foo, fetched from /articles/bar. Stage 9 path binding rejects with E_BIND_PATH.",
        spec_refs=["§02", "§10"],
        verdict="reject",
        diagnostic="E_BIND_PATH",
        body_obj=c,
        context={
            "fetched_path": "/articles/bar",
            "expected_runtime_pubkey": b64u(rp_pub),
        },
    ))

    # /manifest.json as content path - schema-level rejection (rc.6 reservation)
    c_manifest_path = make_content(runtime_priv=rp, path="/manifest.json")
    out.append(vec(
        "171-bind-reserved-manifest-path",
        kind="content",
        description="Content document declaring path /manifest.json. The path is reserved for manifest fetches and the schema rejects it with E_SCHEMA_FIELD_SYNTAX.",
        spec_refs=["§02", "§09"],
        verdict="reject",
        diagnostic="E_SCHEMA_FIELD_SYNTAX",
        body_obj=c_manifest_path,
        context={
            "fetched_path": "/manifest.json",
            "expected_runtime_pubkey": b64u(rp_pub),
        },
    ))

    # transaction with mismatched request_hash
    t, sb = make_transaction(runtime_priv=rp)
    # Tamper the recorded submit body so the locally-computed request_hash
    # differs from the one in the (still valid) transaction.
    sb_tampered = dict(sb)
    sb_tampered["fields"] = {"message": "TAMPERED", "name": "alice"}
    out.append(vec(
        "172-bind-request-hash-mismatch",
        kind="transaction",
        description="Transaction document whose request_hash matches the original submit body, but the client's recorded submit body has been tampered (fields.message changed). Stage 9 rejects with E_BIND_REQUEST_HASH.",
        spec_refs=["§02", "§09"],
        verdict="reject",
        diagnostic="E_BIND_REQUEST_HASH",
        body_obj=t,
        context={
            "submit_path": t["in_response_to"],
            "expected_runtime_pubkey": b64u(rp_pub),
            "submit_body_path": "vectors/172-bind-request-hash-mismatch/submit_body.json",
        },
        extra_files={
            "submit_body.json": json.dumps(
                sb_tampered, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8"),
        },
    ))

    # transaction with mismatched request_id
    # in_response_to and request_hash both match the real (untampered) submit
    # body, so E_BIND_REQUEST_ID is the only live Stage 9 violation. The
    # transaction's request_id is an independent copied field, not part of the
    # hashed submit body, so the mismatch isolates from E_BIND_REQUEST_HASH.
    t_rid, sb_rid = make_transaction(
        runtime_priv=rp,
        request_id_override="BAECAwQFBgcICQoLDA0ODw",
    )
    out.append(vec(
        "173-bind-request-id-mismatch",
        kind="transaction",
        description="Transaction document whose request_id (BAECAwQFBgcICQoLDA0ODw) differs from the request_id the client placed in the submit body (AAECAwQFBgcICQoLDA0ODw). in_response_to matches the submit path and request_hash matches the recorded (untampered) submit body, so the request_id binding is the only live Stage 9 violation. Rejected with E_BIND_REQUEST_ID. The transaction's request_id is an independent copied field, not part of the hashed submit body, so it isolates cleanly from E_BIND_REQUEST_HASH.",
        spec_refs=["§02", "§09"],
        verdict="reject",
        diagnostic="E_BIND_REQUEST_ID",
        body_obj=t_rid,
        context={
            "submit_path": t_rid["in_response_to"],
            "expected_runtime_pubkey": b64u(rp_pub),
            "submit_body_path": "vectors/173-bind-request-id-mismatch/submit_body.json",
        },
        extra_files={
            "submit_body.json": json.dumps(
                sb_rid, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8"),
        },
    ))

    # ---- canary: equal issued_at conflict ----
    m_alt = make_manifest(
        publisher_priv=pp, publisher_pub=pp_pub,
        origin_pub=op_pub, runtime_pub=keys["runtime_pub_2"],
        # same issued_at as 001
    )
    out.append(vec(
        "180-canary-equal-issued-at-conflict",
        kind="manifest",
        description="Two manifests with the same canary.issued_at and the same K_publisher.pub but different runtime_pubkey. Once 001 is verified and retained, observing this manifest at the same issued_at must produce E_CANARY_CONFLICT.",
        spec_refs=["§08"],
        verdict="reject",
        diagnostic="E_CANARY_CONFLICT",
        body_obj=m_alt,
        context={
            "fetched_origin_address": m_alt["origin"]["address"]
        ,
            "previously_verified": "vectors/001-manifest-valid-minimal/input.json",
        },
    ))

    # ---- additional sig strictness: non-canonical R, non-canonical A ----
    # Non-canonical R: replace R with an encoding whose y portion equals
    # 2^255 - 1, which exceeds the Ed25519 prime p = 2^255 - 19. RFC 8032
    # requires y < p; the strict profile rejects this encoding before the
    # cryptographic verification equation is evaluated. S is left unchanged
    # at the value from the original valid signature on m, but the R
    # rejection takes precedence.
    real_sig_bytes = b64u_decode(m["sig"])
    nc_r_sig = non_canonical_r_encoding() + real_sig_bytes[32:]
    m_nc_r = dict(m)
    m_nc_r["sig"] = b64u(nc_r_sig)
    out.append(vec(
        "154-sig-non-canonical-r",
        kind="manifest",
        description="Manifest whose signature R has a non-canonical compressed point encoding (y >= p). The strict profile (§05) rejects non-canonical encodings of R independently of any verification equation. E_SIG_VERIFICATION.",
        spec_refs=["§05"],
        verdict="reject",
        diagnostic="E_SIG_VERIFICATION",
        body_obj=m_nc_r,
        context={"fetched_origin_address": m_nc_r["origin"]["address"]},
    ))

    # Non-canonical A: replace publisher_pubkey with the same all-0xff
    # encoding; the strict profile (§05) rejects A whose y portion exceeds
    # the field prime, before any signature check. The sig field is left
    # at the original valid value; the A rejection happens first.
    m_nc_a = dict(m)
    m_nc_a["publisher_pubkey"] = b64u(non_canonical_r_encoding())
    out.append(vec(
        "155-sig-non-canonical-a",
        kind="manifest",
        description="Manifest whose publisher_pubkey is a non-canonical Ed25519 point encoding (y >= p). The strict profile (§05) rejects non-canonical encodings of A before signature verification. E_SIG_VERIFICATION.",
        spec_refs=["§05"],
        verdict="reject",
        diagnostic="E_SIG_VERIFICATION",
        body_obj=m_nc_a,
        context={"fetched_origin_address": m_nc_a["origin"]["address"]},
    ))

    # ---- canary: anti-downgrade on issued_at ----
    # A manifest with strictly older issued_at than 001's (2026-05-07).
    # The vector context references 001 as previously verified, so the
    # client's anti-downgrade rule must reject this manifest as a downgrade.
    m_old = make_manifest(
        publisher_priv=pp, publisher_pub=pp_pub,
        origin_pub=op_pub, runtime_pub=rp_pub,
        issued_at="2026-04-01T00:00:00Z",
        next_expected="2026-05-01T00:00:00Z",
        updated="2026-04-01T00:00:00Z",
    )
    out.append(vec(
        "181-canary-issued-at-downgrade",
        kind="manifest",
        description="Manifest with canary.issued_at strictly older than the issued_at of a previously verified manifest (001) for the same K_publisher.pub. The client's anti-downgrade rule (§08) rejects with E_CANARY_DOWNGRADE.",
        spec_refs=["§08"],
        verdict="reject",
        diagnostic="E_CANARY_DOWNGRADE",
        body_obj=m_old,
        context={
            "fetched_origin_address": m_old["origin"]["address"],
            "previously_verified": "vectors/001-manifest-valid-minimal/input.json",
        },
    ))

    # ---- Unicode normalization: NFD canary.statement ----
    # The publisher must encode user-visible strings in NFC (§04). A
    # canary.statement using decomposed combining marks (NFD) instead of
    # precomposed characters (NFC) is rejected at schema validation. The
    # statement "Café" in NFD is "Cafe" + U+0301 (combining acute).
    nfd_statement = "Cafe\u0301"  # NFD form of "Café"
    # Build a manifest with this statement directly. We sign it (the JCS bytes
    # over the NFD payload differ from the NFC equivalent), so the signature
    # itself is valid; the rejection is at schema validation, before sig check.
    m_nfd_payload = {
        "spec_version": "1.0",
        "kind": "manifest",
        "publisher_pubkey": b64u(pp_pub),
        "origin": {
            "carrier": "tor-v3",
            "address": onion_address(op_pub),
            "origin_pubkey": b64u(op_pub),
        },
        "canary": {
            "runtime_pubkey": b64u(rp_pub),
            "issued_at": "2026-05-07T00:00:00Z",
            "next_expected": "2026-06-06T00:00:00Z",
            "statement": nfd_statement,
        },
        "state_policy": [],
        "navigation": [],
        "min_refresh_interval": 3600,
        "updated": "2026-05-07T00:00:00Z",
    }
    m_nfd_payload["sig"] = sign(pp, CTX_MANIFEST, m_nfd_payload)
    out.append(vec(
        "190-unicode-nfd-statement",
        kind="manifest",
        description="Manifest whose canary.statement contains a decomposed combining mark (NFD) rather than the precomposed NFC form. Per §04, user-visible strings must be in NFC. Rejected at schema validation with E_SCHEMA_FIELD_SYNTAX before signature verification.",
        spec_refs=["§04", "§08"],
        verdict="reject",
        diagnostic="E_SCHEMA_FIELD_SYNTAX",
        body_obj=m_nfd_payload,
        context={"fetched_origin_address": m_nfd_payload["origin"]["address"]},
    ))

    # ---- 200: migration scenario, successor manifest origin-expired ----
    #
    # Announcing manifest at the original origin (op_pub) carries a
    # migration_pointer to a successor origin (op_pub_2). The successor
    # manifest is signed correctly by the same K_publisher and binds correctly
    # to the successor address, but its own origin.not_after has already
    # passed at clock_now (2026-05-07). The successor therefore fails Stage 9
    # in isolation with E_ORIGIN_EXPIRED. Per §10 "Successor verification" and
    # §11, the migration is rejected under E_MIGRATION_MISMATCH with
    # mismatch_field="successor_stage9_failure" and underlying_diagnostic_code
    # ="E_ORIGIN_EXPIRED". The announcing manifest is itself accepted at its
    # origin (verdict reject here refers to the migration adoption outcome).
    op_pub_2 = keys["origin_pub_2"]
    successor_address = onion_address(op_pub_2)
    successor = make_manifest(
        publisher_priv=pp, publisher_pub=pp_pub,
        origin_pub=op_pub_2, runtime_pub=rp_pub,
        issued_at="2026-04-01T00:00:00Z",
        next_expected="2026-05-01T00:00:00Z",
        updated="2026-04-01T00:00:00Z",
        not_after="2026-05-01T00:00:00Z",  # past relative to clock_now
    )
    successor_bytes = json.dumps(
        successor, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    announcing = make_manifest(
        publisher_priv=pp, publisher_pub=pp_pub,
        origin_pub=op_pub, runtime_pub=rp_pub,
        migration_pointer={
            "successor_origin": {
                "carrier": "tor-v3",
                "address": successor_address,
                "origin_pubkey": b64u(op_pub_2),
            },
            "announced_at": "2026-05-07T00:00:00Z",
        },
    )
    out.append(vec(
        "200-migration-successor-origin-expired",
        kind="manifest",
        description=(
            "Migration scenario exercising the rc.15 successor_stage9_failure path. "
            "The announcing manifest at the original origin is itself valid and accepted "
            "in isolation; it carries a migration_pointer to a successor origin. The "
            "successor manifest (in extra_files/successor_manifest.json) is signed "
            "correctly by the same K_publisher and binds to the successor address per "
            "the Tor v3 derivation rule, but its own origin.not_after has already "
            "passed at clock_now (2026-05-07). The successor fails Stage 9 in isolation "
            "with E_ORIGIN_EXPIRED. Per §10 'Successor verification', the migration "
            "is rejected under E_MIGRATION_MISMATCH; per §11, details.mismatch_field "
            "= 'successor_stage9_failure' and details.underlying_diagnostic_code = "
            "'E_ORIGIN_EXPIRED'. The reject verdict here refers to the migration "
            "adoption outcome, not to the announcing manifest itself."
        ),
        spec_refs=["§06", "§10", "§11"],
        verdict="reject",
        diagnostic="E_MIGRATION_MISMATCH",
        diagnostic_details={
            "mismatch_field": "successor_stage9_failure",
            "underlying_diagnostic_code": "E_ORIGIN_EXPIRED",
        },
        body_obj=announcing,
        context={
            "fetched_origin_address": announcing["origin"]["address"],
            "successor_origin_address": successor_address,
            "successor_manifest_path": "vectors/200-migration-successor-origin-expired/successor_manifest.json",
        },
        extra_files={
            "successor_manifest.json": successor_bytes,
        },
    ))

    # =====================================================================
    # rc.18 Phase-1 additions: pipeline coverage within the existing
    # vector schema. These vectors target §11 diagnostic codes that had
    # zero coverage in the rc.17 corpus. Each is constructed so that
    # the diagnostic-relevant violation is the only live violation at the
    # first failing pipeline stage (corpus isolation rule, see README).
    # =====================================================================

    # ---- 102-input-byte-cap (Stage 2, E_INPUT_BYTE_CAP) ----
    # Manifest-shaped body padded past the 64 KiB Stage 2 byte cap.
    # Stage 2 fires before Stage 3 JSON parsing, so the JSON well-formedness
    # below the cap is irrelevant.
    out.append(vec(
        "102-input-byte-cap",
        kind="manifest",
        description=(
            "Manifest-shaped body padded past the 64 KiB byte cap for "
            "manifests (§02). Stage 2 input check fires before Stage 3 JSON "
            "parsing; well-formedness of the JSON below the cap is therefore "
            "irrelevant. E_INPUT_BYTE_CAP."
        ),
        spec_refs=["§02", "§04"],
        verdict="reject",
        diagnostic="E_INPUT_BYTE_CAP",
        body=(
            b'{"spec_version":"1.0","kind":"manifest","_pad":"'
            + (b"A" * 70000)
            + b'"}'
        ),
    ))

    # ---- 111-parse-nesting-depth (Stage 3, E_PARSE_NESTING_DEPTH) ----
    # Nested JSON array of depth 20 exceeds the 16-level Stage 3 cap.
    out.append(vec(
        "111-parse-nesting-depth",
        kind="manifest",
        description=(
            "Manifest body containing a 20-level-deep nested array, "
            "exceeding the 16-level Stage 3 nesting cap (§04). The field "
            "below the cap is irrelevant; Stage 3 fires before Stage 5. "
            "E_PARSE_NESTING_DEPTH."
        ),
        spec_refs=["§04"],
        verdict="reject",
        diagnostic="E_PARSE_NESTING_DEPTH",
        body=(
            b'{"spec_version":"1.0","kind":"manifest","_nest":'
            + b"[" * 20 + b"0" + b"]" * 20
            + b',"sig":"' + (b"A" * 86) + b'"}'
        ),
    ))

    # ---- 112-parse-string-length (Stage 3, E_PARSE_STRING_LENGTH) ----
    # Content document containing a code_block whose content is a string
    # one byte above the 100 KiB Stage 3 string cap. Body sits well under
    # the 1 MiB content byte cap so Stage 2 passes.
    long_str = b"x" * (100 * 1024 + 1)  # 102401 bytes
    out.append(vec(
        "112-parse-string-length",
        kind="content",
        description=(
            "Content document containing a single string of 102401 ASCII "
            "bytes, one byte above the 100 KiB Stage 3 string cap (§04). "
            "Body remains under the 1 MiB content byte cap so Stage 2 "
            "passes and Stage 3 fires. E_PARSE_STRING_LENGTH."
        ),
        spec_refs=["§04"],
        verdict="reject",
        diagnostic="E_PARSE_STRING_LENGTH",
        body=(
            b'{"spec_version":"1.0","kind":"content","path":"/x","meta":'
            b'{"title":"t","published_at":"2026-05-07T00:00:00Z"},'
            b'"blocks":[{"kind":"code_block","language":"text","content":"'
            + long_str + b'"}],"sig":"' + (b"A" * 86) + b'"}'
        ),
    ))

    # ---- 116-parse-string-length-utf8-unit (Stage 3, E_PARSE_STRING_LENGTH;
    #      AMB-15) ----
    # The 100 KiB Stage 3 string cap is counted in UTF-8 wire bytes (§02,
    # §10; AMB-15 / rc.30), not UTF-16 code units. This code_block content is
    # 30000 repetitions of U+1F600 (a non-BMP code point: 4 UTF-8 bytes, but
    # only 2 UTF-16 code units each) = 120000 UTF-8 bytes (over the 102400
    # cap) but 60000 UTF-16 code units (under it). An implementation counting
    # UTF-8 bytes REJECTS with E_PARSE_STRING_LENGTH; one counting UTF-16 code
    # units would wrongly accept. The body stays well under the 1 MiB Stage 2
    # cap, so Stage 2 passes and Stage 3 fires. U+1F600 is not a control
    # character and is already NFC, so no earlier check pre-empts the cap.
    emoji = b"\xf0\x9f\x98\x80" * 30000  # U+1F600 x 30000 = 120000 UTF-8 bytes
    out.append(vec(
        "116-parse-string-length-utf8-unit",
        kind="content",
        description=(
            "Content document whose code_block content is 30000 U+1F600 "
            "code points = 120000 UTF-8 wire bytes (over the 100 KiB Stage 3 "
            "string cap) but only 60000 UTF-16 code units (under it). Per "
            "§02/§10 (AMB-15) the cap is counted in UTF-8 wire bytes, so this "
            "is rejected with E_PARSE_STRING_LENGTH; an implementation "
            "counting UTF-16 code units would wrongly accept. Body is under "
            "the 1 MiB Stage 2 cap so Stage 3 fires."
        ),
        spec_refs=["§02", "§04", "§10"],
        verdict="reject",
        diagnostic="E_PARSE_STRING_LENGTH",
        body=(
            b'{"spec_version":"1.0","kind":"content","path":"/x","meta":'
            b'{"title":"t","published_at":"2026-05-07T00:00:00Z"},'
            b'"blocks":[{"kind":"code_block","language":"text","content":"'
            + emoji + b'"}],"sig":"' + (b"A" * 86) + b'"}'
        ),
    ))

    # ---- 113-parse-array-length (Stage 3, E_PARSE_ARRAY_LENGTH) ----
    # Content document whose blocks array contains 10001 entries, one above
    # the 10000-element Stage 3 array cap. Element shapes are irrelevant;
    # Stage 3 fires before Stage 5 schema validation.
    out.append(vec(
        "113-parse-array-length",
        kind="content",
        description=(
            "Content document whose blocks array contains 10001 entries, "
            "one above the 10000-element Stage 3 array cap (§04). Element "
            "shapes are irrelevant; Stage 3 fires before Stage 5. "
            "E_PARSE_ARRAY_LENGTH."
        ),
        spec_refs=["§04"],
        verdict="reject",
        diagnostic="E_PARSE_ARRAY_LENGTH",
        body=(
            b'{"spec_version":"1.0","kind":"content","path":"/x","meta":'
            b'{"title":"t","published_at":"2026-05-07T00:00:00Z"},'
            b'"blocks":[' + b"{}," * 10000 + b"{}]"
            + b',"sig":"' + (b"A" * 86) + b'"}'
        ),
    ))

    # ---- 117/118: Stage 3 parser limit co-occurring with a non-integer (AMB-29)
    # When a non-conforming numeric token (here the float 1.5) co-occurs with a
    # structural Stage 3 parser-limit violation, the lower-numbered Stage 3 limit
    # wins (§11:15 first-failing-stage; the numeric-grammar stage is
    # implementation-defined per §04:101). So the diagnostic is the E_PARSE_*
    # limit code, not E_SCHEMA_NON_INTEGER. Pairs with 111/113 (same limits, a
    # conforming value at the violation site) and 140 (a float with no Stage 3
    # limit -> E_SCHEMA_NON_INTEGER).
    out.append(vec(
        "117-parse-nesting-depth-with-float",
        kind="manifest",
        description=(
            "Manifest body with a 20-level-deep nested array (exceeding the "
            "16-level Stage 3 nesting cap, §04) whose innermost value is the "
            "non-conforming numeric token 1.5. The structural Stage 3 limit and "
            "the numeric-grammar violation co-occur; per AMB-29 the lower-"
            "numbered Stage 3 limit wins, so the diagnostic is "
            "E_PARSE_NESTING_DEPTH, not E_SCHEMA_NON_INTEGER."
        ),
        spec_refs=["§04", "§10", "§11"],
        verdict="reject",
        diagnostic="E_PARSE_NESTING_DEPTH",
        body=(
            b'{"spec_version":"1.0","kind":"manifest","_nest":'
            + b"[" * 20 + b"1.5" + b"]" * 20
            + b',"sig":"' + (b"A" * 86) + b'"}'
        ),
    ))

    out.append(vec(
        "118-parse-array-length-with-float",
        kind="content",
        description=(
            "Content document whose blocks array contains 10001 entries (one "
            "above the 10000-element Stage 3 array cap, §04), one of which is "
            "the non-conforming numeric token 1.5. The structural Stage 3 limit "
            "and the numeric-grammar violation co-occur; per AMB-29 the lower-"
            "numbered Stage 3 limit wins, so the diagnostic is "
            "E_PARSE_ARRAY_LENGTH, not E_SCHEMA_NON_INTEGER."
        ),
        spec_refs=["§04", "§10", "§11"],
        verdict="reject",
        diagnostic="E_PARSE_ARRAY_LENGTH",
        body=(
            b'{"spec_version":"1.0","kind":"content","path":"/x","meta":'
            b'{"title":"t","published_at":"2026-05-07T00:00:00Z"},'
            b'"blocks":[' + b"{}," * 10000 + b"1.5]"
            + b',"sig":"' + (b"A" * 86) + b'"}'
        ),
    ))

    # ---- 114-parse-object-keys (Stage 3, E_PARSE_OBJECT_KEYS) ----
    # Content document whose meta object contains 257 members, one above
    # the 256-key Stage 3 object cap. Member names beyond the meta schema
    # are irrelevant; Stage 3 fires before Stage 5.
    extra_keys = b",".join(b'"k%d":0' % i for i in range(255))
    out.append(vec(
        "114-parse-object-keys",
        kind="content",
        description=(
            "Content document whose meta object contains 257 members, one "
            "above the 256-key Stage 3 object cap (§04). Member names "
            "beyond the meta schema are irrelevant; Stage 3 fires before "
            "Stage 5. E_PARSE_OBJECT_KEYS."
        ),
        spec_refs=["§04"],
        verdict="reject",
        diagnostic="E_PARSE_OBJECT_KEYS",
        body=(
            b'{"spec_version":"1.0","kind":"content","path":"/x","meta":'
            b'{"title":"t","published_at":"2026-05-07T00:00:00Z",'
            + extra_keys
            + b'},"blocks":[{"kind":"divider"}],"sig":"'
            + (b"A" * 86) + b'"}'
        ),
    ))

    # ---- 115-parse-json-malformed (Stage 3, E_PARSE_JSON) ----
    # Body containing a trailing comma followed by a missing value; not
    # parseable as JSON.
    out.append(vec(
        "115-parse-json-malformed",
        kind="manifest",
        description=(
            "Body is not parseable as JSON: trailing comma followed by a "
            "missing value at \"sig\". Stage 3 JSON parsing rejects with "
            "E_PARSE_JSON."
        ),
        spec_refs=["§04"],
        verdict="reject",
        diagnostic="E_PARSE_JSON",
        body=b'{"spec_version":"1.0","kind":"manifest","sig":,}',
    ))

    # ---- 122-kind-missing-fields (Stage 4, E_KIND_MISSING_FIELDS) ----
    # Document with the top-level sig field omitted. spec_version and kind
    # are present and well-formed, but sig - one of the three top-level
    # required fields per §02 - is absent. Stage 4 detects this before
    # Stage 5 schema would also flag it.
    out.append(vec(
        "122-kind-missing-fields",
        kind="manifest",
        description=(
            "Document with the top-level sig field omitted. spec_version "
            "and kind are present and well-formed, but sig - one of the "
            "three top-level required fields per §02 - is absent. Stage 4 "
            "kind discrimination fires E_KIND_MISSING_FIELDS."
        ),
        spec_refs=["§02", "§11"],
        verdict="reject",
        diagnostic="E_KIND_MISSING_FIELDS",
        body=b'{"spec_version":"1.0","kind":"manifest"}',
    ))

    # ---- 134-schema-field-type (Stage 5, E_SCHEMA_FIELD_TYPE) ----
    # Manifest where min_refresh_interval is the string "3600" instead of
    # a non-negative integer. Stage 5 fires before Stage 6 signature
    # verification, so the residual signature is irrelevant.
    m_field_type = dict(m)
    m_field_type["min_refresh_interval"] = "3600"
    out.append(vec(
        "134-schema-field-type",
        kind="manifest",
        description=(
            "Manifest where min_refresh_interval is the string \"3600\" "
            "instead of a non-negative integer. Stage 5 closed-schema "
            "validation fires before Stage 6 signature verification "
            "(§10 first-failing-stage). E_SCHEMA_FIELD_TYPE."
        ),
        spec_refs=["§06", "§11"],
        verdict="reject",
        diagnostic="E_SCHEMA_FIELD_TYPE",
        body_obj=m_field_type,
        context={"fetched_origin_address": m_field_type["origin"]["address"]},
    ))

    # ---- 135-schema-field-range (Stage 5, E_SCHEMA_FIELD_RANGE) ----
    # Content document with a heading block whose level is 7, outside the
    # [1..6] range required by §03.
    c_bad_range = make_content(
        runtime_priv=rp,
        path="/articles/bad-range",
        title="Bad range",
        blocks=[{
            "kind": "heading",
            "level": 7,
            "content": [
                {"kind": "text", "value": "Too deep", "marks": []},
            ],
        }],
    )
    out.append(vec(
        "135-schema-field-range",
        kind="content",
        description=(
            "Content document containing a heading block whose level is "
            "7, outside the [1..6] range required by §03. Stage 5 schema "
            "rejects with E_SCHEMA_FIELD_RANGE before Stage 6 signature "
            "verification."
        ),
        spec_refs=["§03", "§11"],
        verdict="reject",
        diagnostic="E_SCHEMA_FIELD_RANGE",
        body_obj=c_bad_range,
        context={
            "fetched_path": c_bad_range["path"],
            "expected_runtime_pubkey": b64u(rp_pub),
        },
    ))

    # ---- 136-schema-block-not-permitted (Stage 5, E_SCHEMA_BLOCK_NOT_PERMITTED) ----
    # Transaction document whose blocks contains a submit_form block.
    # submit_form is permitted only in content documents per §03's
    # "Block usage by document kind" table.
    sb_136 = {
        "fields": {},
        "request_state": [],
        "request_id": "AAECAwQFBgcICQoLDA0ODw",
    }
    t_136, _ = make_transaction(
        runtime_priv=rp,
        submit_body=sb_136,
        blocks=[{
            "kind": "submit_form",
            "label": [
                {"kind": "text", "value": "Send a message", "marks": []},
            ],
            "submit_to": "/contact",
            "fields": [
                {
                    "kind": "textarea",
                    "name": "message",
                    "label": "Message",
                    "required": True,
                    "max_length": 1000,
                }
            ],
            "submit_label": "Send",
        }],
    )
    out.append(vec(
        "136-schema-block-not-permitted",
        kind="transaction",
        description=(
            "Transaction document whose blocks array contains a "
            "submit_form block. submit_form is permitted only in content "
            "documents per §03 \"Block usage by document kind\". Stage 5 "
            "schema rejects with E_SCHEMA_BLOCK_NOT_PERMITTED."
        ),
        spec_refs=["§02", "§03"],
        verdict="reject",
        diagnostic="E_SCHEMA_BLOCK_NOT_PERMITTED",
        body_obj=t_136,
        context={
            "submit_path": t_136["in_response_to"],
            "expected_runtime_pubkey": b64u(rp_pub),
            "submit_body_path": "vectors/136-schema-block-not-permitted/submit_body.json",
        },
        extra_files={
            "submit_body.json": json.dumps(
                sb_136, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8"),
        },
    ))

    # ---- 137-schema-duplicate-entry (Stage 5, E_SCHEMA_DUPLICATE_ENTRY) ----
    # Manifest whose state_policy declares two entries with identical
    # (namespace, key). §06 requires (namespace, key) uniqueness across
    # state_policy entries.
    m_dup_policy = make_manifest(
        publisher_priv=pp, publisher_pub=pp_pub,
        origin_pub=op_pub, runtime_pub=rp_pub,
        state_policy=[
            {
                "namespace": "session",
                "key": "auth",
                "mode": "request",
                "max_size": 512,
                "max_lifetime": 86400,
                "purpose": "First entry.",
            },
            {
                "namespace": "session",
                "key": "auth",
                "mode": "client_only",
                "max_size": 256,
                "max_lifetime": 7776000,
                "purpose": "Duplicate (namespace, key).",
            },
        ],
    )
    out.append(vec(
        "137-schema-duplicate-entry",
        kind="manifest",
        description=(
            "Manifest whose state_policy contains two entries with "
            "identical (namespace, key) = (\"session\", \"auth\"). §06 "
            "requires (namespace, key) uniqueness across state_policy "
            "entries. Stage 5 schema rejects with E_SCHEMA_DUPLICATE_ENTRY."
        ),
        spec_refs=["§06", "§07", "§11"],
        verdict="reject",
        diagnostic="E_SCHEMA_DUPLICATE_ENTRY",
        body_obj=m_dup_policy,
        context={"fetched_origin_address": m_dup_policy["origin"]["address"]},
    ))

    # ---- 138-schema-malformed-unicode (Stage 5, E_SCHEMA_MALFORMED_UNICODE) ----
    # Manifest whose canary.statement contains the JSON escape sequence
    # \uD800 - a lone high surrogate with no paired low surrogate. RFC 8259
    # admits the escape syntactically; §04 rejects the resulting isolated
    # surrogate code point at schema validation. Raw bytes are used so the
    # surrogate appears literally in the wire form (Python's UTF-8 encoder
    # would otherwise refuse to emit it).
    out.append(vec(
        "138-schema-malformed-unicode",
        kind="manifest",
        description=(
            "Manifest whose canary.statement contains the JSON escape "
            "sequence \\uD800 - a lone high surrogate with no paired low "
            "surrogate. After JSON parsing this yields a string with an "
            "isolated surrogate code point, which §04 rejects as malformed "
            "Unicode at Stage 5 schema validation (before Stage 6 signature "
            "verification). Conforming parsers accept the JSON escape per "
            "RFC 8259 §7; rejection is at the schema layer. "
            "E_SCHEMA_MALFORMED_UNICODE."
        ),
        spec_refs=["§04", "§11"],
        verdict="reject",
        diagnostic="E_SCHEMA_MALFORMED_UNICODE",
        body=(
            b'{"spec_version":"1.0","kind":"manifest","publisher_pubkey":"'
            + b64u(pp_pub).encode("ascii")
            + b'","origin":{"carrier":"tor-v3","address":"'
            + onion_address(op_pub).encode("ascii")
            + b'","origin_pubkey":"'
            + b64u(op_pub).encode("ascii")
            + b'"},"canary":{"runtime_pubkey":"'
            + b64u(rp_pub).encode("ascii")
            + b'","issued_at":"2026-05-07T00:00:00Z",'
            b'"next_expected":"2026-06-06T00:00:00Z",'
            b'"statement":"Lone surrogate: \\uD800."},'
            b'"state_policy":[],"navigation":[],'
            b'"min_refresh_interval":3600,'
            b'"updated":"2026-05-07T00:00:00Z","sig":"'
            + (b"A" * 86) + b'"}'
        ),
    ))

    # ---- 175-bind-origin (Stage 9, E_BIND_ORIGIN) ----
    # Otherwise-valid manifest binding origin to K_origin (op_pub), but
    # fetched from the address derived from K_origin_2 (op_pub_2). Stage 9
    # Tor v3 address-to-key derivation fires the binding error.
    m_175 = make_manifest(
        publisher_priv=pp, publisher_pub=pp_pub,
        origin_pub=op_pub, runtime_pub=rp_pub,
    )
    wrong_origin_address = onion_address(keys["origin_pub_2"])
    out.append(vec(
        "175-bind-origin",
        kind="manifest",
        description=(
            "Otherwise-valid manifest whose origin binds to K_origin (test "
            "fixture), fetched from the onion address derived from K_origin_2. "
            "Stage 9 Tor v3 address-to-key derivation produces an "
            "origin_pubkey that does not match manifest.origin.origin_pubkey. "
            "E_BIND_ORIGIN."
        ),
        spec_refs=["§05", "§09", "§10"],
        verdict="reject",
        diagnostic="E_BIND_ORIGIN",
        body_obj=m_175,
        context={"fetched_origin_address": wrong_origin_address},
    ))

    # ---- 179-bind-origin-small-order-pubkey (Stage 9, E_BIND_ORIGIN;
    #      AMB-17) ----
    # origin.origin_pubkey is the encoded identity point SMALL_ORDER_A
    # (small-order, order 1). origin.address is derived from that same key
    # so the Tor v3 address-to-key binding MATCHES (the address decodes to
    # the declared origin_pubkey) -- isolating the violation to the §05
    # public-key validity profile: K_origin.pub is a small-order point. Per
    # §05:159 the strict profile applies to K_origin.pub; AMB-17 (rc.33)
    # pins enforcement at Stage 9 origin binding with E_BIND_ORIGIN (K_origin
    # verifies no document, so E_SIG_VERIFICATION has no trigger here). The
    # manifest is signed correctly by K_publisher so the small-order origin
    # key is the only live violation.
    m_179 = make_manifest(
        publisher_priv=pp, publisher_pub=pp_pub,
        origin_pub=op_pub, runtime_pub=rp_pub,
    )
    del m_179["sig"]
    smallorder_addr = onion_address(SMALL_ORDER_A)
    m_179["origin"]["origin_pubkey"] = b64u(SMALL_ORDER_A)
    m_179["origin"]["address"] = smallorder_addr
    m_179["sig"] = sign(pp, CTX_MANIFEST, m_179)
    out.append(vec(
        "179-bind-origin-small-order-pubkey",
        kind="manifest",
        description=(
            "Manifest whose origin.origin_pubkey is a small-order point "
            "(the encoded identity point), with origin.address derived from "
            "that same key so the Tor v3 address-to-key binding matches and "
            "the only violation is that K_origin.pub fails the §05 "
            "small-order rejection. Per §05:159 the strict profile applies "
            "to K_origin.pub; AMB-17 pins enforcement at Stage 9 origin "
            "binding with E_BIND_ORIGIN (K_origin verifies no document, so "
            "E_SIG_VERIFICATION has no trigger). Signed correctly by "
            "K_publisher so the small-order origin key is the only live "
            "violation."
        ),
        spec_refs=["§05", "§09", "§11"],
        verdict="reject",
        diagnostic="E_BIND_ORIGIN",
        body_obj=m_179,
        context={"fetched_origin_address": smallorder_addr},
    ))

    # ---- 176-origin-invalid (E_ORIGIN_INVALID) ----
    # Manifest whose origin.not_after equals canary.issued_at. §06 requires
    # not_after to be strictly later than canary.issued_at; equal violates
    # the MUST.
    m_176 = make_manifest(
        publisher_priv=pp, publisher_pub=pp_pub,
        origin_pub=op_pub, runtime_pub=rp_pub,
        not_after="2026-05-07T00:00:00Z",  # equal to canary.issued_at
    )
    out.append(vec(
        "176-origin-invalid",
        kind="manifest",
        description=(
            "Manifest whose origin.not_after equals canary.issued_at "
            "(2026-05-07T00:00:00Z). §06 requires not_after strictly later "
            "than canary.issued_at; equality violates the MUST. The "
            "manifest is signed correctly and otherwise valid. "
            "E_ORIGIN_INVALID."
        ),
        spec_refs=["§06", "§11"],
        verdict="reject",
        diagnostic="E_ORIGIN_INVALID",
        body_obj=m_176,
        context={"fetched_origin_address": m_176["origin"]["address"]},
    ))

    # ---- 182-canary-invalid (Stage 8, E_CANARY_INVALID) ----
    # Canary interval (next_expected - issued_at) is 6 days, below the
    # 7-day minimum required by §08. All other fields are valid and the
    # manifest is signed correctly. Canary is fresh at clock_now.
    m_182 = make_manifest(
        publisher_priv=pp, publisher_pub=pp_pub,
        origin_pub=op_pub, runtime_pub=rp_pub,
        issued_at="2026-05-06T00:00:00Z",
        next_expected="2026-05-12T00:00:00Z",  # 6 days, below 7-day floor
        updated="2026-05-06T00:00:00Z",
    )
    out.append(vec(
        "182-canary-invalid",
        kind="manifest",
        description=(
            "Manifest whose canary interval (next_expected - issued_at) is "
            "6 days, below the 7-day minimum required by §08. The manifest "
            "is otherwise well-formed and signed correctly; canary is fresh "
            "at clock_now (2026-05-07). Stage 8 canary validation fires "
            "E_CANARY_INVALID."
        ),
        spec_refs=["§08", "§11"],
        verdict="reject",
        diagnostic="E_CANARY_INVALID",
        body_obj=m_182,
        context={"fetched_origin_address": m_182["origin"]["address"]},
    ))

    # =====================================================================
    # rc.19 Lotto 16 corpus additions: vectors filling diagnostic codes
    # that remained zero-covered after rc.18 Phase-1 but are reachable
    # within the existing single-document or already-supported
    # multi-manifest schema. Each vector observes the corpus isolation
    # rule (only the targeted diagnostic-relevant violation is live at
    # the first failing pipeline stage).
    # =====================================================================

    # ---- 139-schema-field-length (Stage 5, E_SCHEMA_FIELD_LENGTH) ----
    # Manifest whose canary.freshness_proof is a 201-byte ASCII string,
    # one byte above the 200-byte cap declared in §08:118. The string is
    # well within the Stage 3 100 KiB parser cap (§04) so Stage 3 passes;
    # Stage 5 schema validation fires the field-specific length cap as
    # distinct from the parser-level cap that E_PARSE_STRING_LENGTH
    # covers. ASCII is NFC and contains no control characters so the only
    # live violation at the first failing stage is the length cap on
    # freshness_proof (corpus isolation rule). statement is left at its
    # normal short valid value from make_manifest; freshness_proof is
    # optional, this vector explicitly adds it to exercise the cap.
    fp_201 = "x" * 201
    m_139 = make_manifest(
        publisher_priv=pp, publisher_pub=pp_pub,
        origin_pub=op_pub, runtime_pub=rp_pub,
    )
    m_139["canary"]["freshness_proof"] = fp_201
    m_139["sig"] = sign(pp, CTX_MANIFEST, m_139)
    out.append(vec(
        "139-schema-field-length",
        kind="manifest",
        description=(
            "Manifest whose canary.freshness_proof is a 201-byte ASCII "
            "string, one byte above the 200-byte cap declared in "
            "§08:118. The string is well within the Stage 3 100 KiB "
            "parser cap (§04) so Stage 3 passes; Stage 5 schema "
            "validation fires E_SCHEMA_FIELD_LENGTH for the "
            "field-specific cap, distinct from the parser-level "
            "E_PARSE_STRING_LENGTH (vector 112)."
        ),
        spec_refs=["§08", "§11"],
        verdict="reject",
        diagnostic="E_SCHEMA_FIELD_LENGTH",
        body_obj=m_139,
        context={"fetched_origin_address": m_139["origin"]["address"]},
    ))

    # ---- 156-sig-invalid-key-no-manifest (Stage 6, E_SIG_INVALID_KEY) ----
    # Content document presented without any previously verified manifest
    # for its publisher. Per §11:175, the absence of an authorized
    # runtime_pubkey to verify against is E_SIG_INVALID_KEY, distinct
    # from E_SIG_VERIFICATION (signature decoded and the verify equation
    # failed). The content body and signature are themselves well-formed;
    # the failure is the missing key context. Vector context deliberately
    # omits `expected_runtime_pubkey` and `previously_verified` to model
    # the no-manifest condition.
    c_156 = make_content(runtime_priv=rp, path="/articles/orphan-content")
    out.append(vec(
        "156-sig-invalid-key-no-manifest",
        kind="content",
        description=(
            "Content document presented without any verified manifest "
            "supplying an authorized runtime_pubkey for the publisher. "
            "Per §11:172,175 the absence of the expected verification "
            "key yields E_SIG_INVALID_KEY, distinct from "
            "E_SIG_VERIFICATION which requires a key that decodes and "
            "fails the verify equation. The content body and signature "
            "are themselves well-formed; the failure is the missing key "
            "context. Vector context deliberately omits "
            "expected_runtime_pubkey and previously_verified."
        ),
        spec_refs=["§05", "§11"],
        verdict="reject",
        diagnostic="E_SIG_INVALID_KEY",
        body_obj=c_156,
        context={"fetched_path": c_156["path"]},
    ))

    # ---- 157-sig-small-order-r (Stage 6, E_SIG_VERIFICATION) ----
    # Manifest whose signature R component is the encoded identity point
    # (small-order, order 1), the same encoding pattern as
    # SMALL_ORDER_A used by vector 153 for the public key. Per §05:174
    # (rc.22 N63), the strict profile rejects small-order R alongside
    # small-order A; the rejection symmetry between A and R was
    # explicitly mandated in N63 to align the spec text with what
    # ed25519-dalek's verify_strict actually does (it rejects R via
    # signature_R.is_small_order() before the verify equation).
    # Pair to vector 153 for A; both fire E_SIG_VERIFICATION.
    # The S half of the signature is left at the value from the
    # original valid signature on m; the small-order R rejection takes
    # precedence over any subsequent verification step.
    real_sig_bytes_157 = b64u_decode(m["sig"])
    small_r_sig = SMALL_ORDER_A + real_sig_bytes_157[32:]
    m_157 = dict(m)
    m_157["sig"] = b64u(small_r_sig)
    out.append(vec(
        "157-sig-small-order-r",
        kind="manifest",
        description=(
            "Manifest whose signature R component is the encoded "
            "identity point (small-order, order 1), the same encoding "
            "pattern as vector 153 uses for the public key A. Per "
            "§05:174 (rc.22 N63), the strict profile rejects small-order "
            "R alongside small-order A, matching the verify_strict mode "
            "in ed25519-dalek (src/verifying.rs) which calls "
            "signature_R.is_small_order() before the verify equation. "
            "Pair to vector 153 for A; both fire E_SIG_VERIFICATION."
        ),
        spec_refs=["§05", "§11"],
        verdict="reject",
        diagnostic="E_SIG_VERIFICATION",
        body_obj=m_157,
        context={"fetched_origin_address": m_157["origin"]["address"]},
    ))

    # ---- 158-link-carrier-url-non-onion-host (Stage 5, E_SCHEMA_FIELD_SYNTAX) ----
    # A carrier link target URL must have a host that is a valid carrier address
    # for the declared carrier; for tor-v3 that is a 56-char onion address plus
    # ".onion" (§03:584). This content document's carrier target uses a clearnet
    # host (example.com) with otherwise-valid URL syntax, so the only live Stage
    # 5 violation is the non-onion host.
    c_carrier_host = make_content(
        runtime_priv=rp,
        path="/external",
        title="External link",
        blocks=[{
            "kind": "link",
            "label": [{"kind": "text", "value": "External site", "marks": []}],
            "target": {
                "kind": "carrier",
                "carrier": "tor-v3",
                "url": "http://example.com/path",
            },
        }],
    )
    out.append(vec(
        "158-link-carrier-url-non-onion-host",
        kind="content",
        description="Content document with a link block whose carrier target URL (http://example.com/path) has a clearnet host instead of a tor-v3 onion address. Per §03:584 a carrier URL host MUST be a valid carrier address for the declared carrier; for tor-v3, a 56-character onion address followed by .onion. The URL is otherwise well-formed (http:// scheme, valid RFC 3986 characters, within the length cap), so the non-onion host is the only live Stage 5 violation. Rejected with E_SCHEMA_FIELD_SYNTAX.",
        spec_refs=["§03", "§11"],
        verdict="reject",
        diagnostic="E_SCHEMA_FIELD_SYNTAX",
        body_obj=c_carrier_host,
        context={
            "fetched_path": c_carrier_host["path"],
            "expected_runtime_pubkey": b64u(rp_pub),
        },
    ))

    # ---- 165/166/167: link target URL RFC 3986 character set (AMB-22) ----
    # §03:586 (carrier) and §03:616 (citation) require the link target url to
    # contain only valid RFC 3986 characters; a byte outside the
    # unreserved/reserved set, or a malformed percent-triplet, is rejected at
    # Stage 5 as E_SCHEMA_FIELD_SYNTAX. Distinct from 158 (a non-onion host that
    # is itself RFC-3986-valid): these exercise the character set and
    # percent-encoding. Each carries a single live violation. Signed by K_runtime.
    c_cite_badchar = make_content(
        runtime_priv=rp, path="/cite-badchar", title="Citation bad char",
        blocks=[{
            "kind": "link",
            "label": [{"kind": "text", "value": "Source", "marks": []}],
            "target": {"kind": "citation", "url": "https://example.org/a<b"},
        }],
    )
    out.append(vec(
        "165-link-citation-url-bad-char",
        kind="content",
        description="Content document with a link block whose citation target URL is https://example.org/a<b. The < (0x3C) is outside the RFC 3986 unreserved/reserved set, so per §03:616 the URL violates its declared character syntax and is rejected at Stage 5 as E_SCHEMA_FIELD_SYNTAX. The https:// scheme and 1 KiB cap are satisfied, so the disallowed character is the only live violation. Signed by K_runtime.",
        spec_refs=["§03", "§11"],
        verdict="reject",
        diagnostic="E_SCHEMA_FIELD_SYNTAX",
        body_obj=c_cite_badchar,
        context={"fetched_path": c_cite_badchar["path"], "expected_runtime_pubkey": b64u(rp_pub)},
    ))

    c_cite_badpct = make_content(
        runtime_priv=rp, path="/cite-badpct", title="Citation bad percent",
        blocks=[{
            "kind": "link",
            "label": [{"kind": "text", "value": "Source", "marks": []}],
            "target": {"kind": "citation", "url": "https://x.org/%ZZ"},
        }],
    )
    out.append(vec(
        "166-link-citation-url-bad-percent",
        kind="content",
        description="Content document with a link block whose citation target URL is https://x.org/%ZZ. The % does not introduce a valid percent-encoded triplet (ZZ are not hex digits), so per §03:616 and RFC 3986 the URL violates its declared syntax and is rejected at Stage 5 as E_SCHEMA_FIELD_SYNTAX. The scheme and length cap are satisfied, so the malformed percent-triplet is the only live violation. Signed by K_runtime.",
        spec_refs=["§03", "§11"],
        verdict="reject",
        diagnostic="E_SCHEMA_FIELD_SYNTAX",
        body_obj=c_cite_badpct,
        context={"fetched_path": c_cite_badpct["path"], "expected_runtime_pubkey": b64u(rp_pub)},
    ))

    c_carrier_badchar = make_content(
        runtime_priv=rp, path="/carrier-badchar", title="Carrier bad char",
        blocks=[{
            "kind": "link",
            "label": [{"kind": "text", "value": "Mirror", "marks": []}],
            "target": {"kind": "carrier", "carrier": "tor-v3",
                       "url": "http://" + onion_address(op_pub) + "/a<b"},
        }],
    )
    out.append(vec(
        "167-link-carrier-url-bad-char",
        kind="content",
        description="Content document with a link block whose carrier target URL is http://<valid 56-char onion>.onion/a<b. The onion host is a valid tor-v3 carrier address, but the < (0x3C) in the path is outside the RFC 3986 unreserved/reserved set, so per §03:586 the URL violates its declared character syntax and is rejected at Stage 5 as E_SCHEMA_FIELD_SYNTAX. The disallowed path character is the only live violation. Signed by K_runtime.",
        spec_refs=["§03", "§11"],
        verdict="reject",
        diagnostic="E_SCHEMA_FIELD_SYNTAX",
        body_obj=c_carrier_badchar,
        context={"fetched_path": c_carrier_badchar["path"], "expected_runtime_pubkey": b64u(rp_pub)},
    ))

    # ---- 168-schema-null-array-element (Stage 5, E_SCHEMA_NULL_VALUE; AMB-25) ----
    # §04 forbids a null literal at ANY position. The existing null vector (132)
    # places null at an object member (navigation); this places it as an array
    # element (content blocks:[null]). Per §04:47 / §11 the code is
    # E_SCHEMA_NULL_VALUE, not E_SCHEMA_FIELD_TYPE. Signed by K_runtime.
    c_null_arr = make_content(
        runtime_priv=rp, path="/null-element", title="Null element", blocks=[None],
    )
    out.append(vec(
        "168-schema-null-array-element",
        kind="content",
        description="Content document whose blocks array contains a JSON null literal as its single element (blocks:[null]). §04 forbids a null literal at any position, including as an array element; per §11 this is E_SCHEMA_NULL_VALUE, not E_SCHEMA_FIELD_TYPE. Distinct from vector 132, which places null at an object member. Signed by K_runtime.",
        spec_refs=["§04", "§11"],
        verdict="reject",
        diagnostic="E_SCHEMA_NULL_VALUE",
        body_obj=c_null_arr,
        context={"fetched_path": c_null_arr["path"], "expected_runtime_pubkey": b64u(rp_pub)},
    ))

    # ---- 177-origin-invalid-beyond-5y (E_ORIGIN_INVALID, second reason) ----
    # Manifest whose origin.not_after is more than 5 years after
    # canary.issued_at. §06 caps not_after at 5 years past issued_at; this
    # vector pairs with 176 (the not_after_not_later_than_issued_at reason)
    # to cover both reason values declared in §11 E_ORIGIN_INVALID
    # structured details.
    m_177 = make_manifest(
        publisher_priv=pp, publisher_pub=pp_pub,
        origin_pub=op_pub, runtime_pub=rp_pub,
        not_after="2031-05-08T00:00:00Z",  # >5y after issued_at 2026-05-07
    )
    out.append(vec(
        "177-origin-invalid-beyond-5y",
        kind="manifest",
        description=(
            "Manifest whose origin.not_after is 2031-05-08, more than 5 "
            "years after canary.issued_at (2026-05-07). §06 forbids "
            "not_after beyond 5 years past issued_at. This vector pairs "
            "with 176 (equal-to-issued_at reason) to cover both reason "
            "values of E_ORIGIN_INVALID structured details "
            "(not_after_beyond_5y vs not_after_not_later_than_issued_at)."
        ),
        spec_refs=["§06", "§11"],
        verdict="reject",
        diagnostic="E_ORIGIN_INVALID",
        diagnostic_details={"reason": "not_after_beyond_5y"},
        body_obj=m_177,
        context={"fetched_origin_address": m_177["origin"]["address"]},
    ))

    # ---- 178-manifest-updated-future-skew (Stage 5, E_SCHEMA_FIELD_SYNTAX) ----
    # Manifest whose `updated` is set to 2026-05-07T00:07:00Z, six minutes
    # ahead of clock_now (2026-05-07T00:01:00Z), exceeding the 300-second
    # future-skew tolerance defined in §10. Per §06:342 and §10:815, this
    # is rejected as E_SCHEMA_FIELD_SYNTAX with structured details
    # reason="future_beyond_skew_tolerance". Distinct from canary
    # issued_at future skew (vector 183, which yields E_CANARY_INVALID).
    m_178 = make_manifest(
        publisher_priv=pp, publisher_pub=pp_pub,
        origin_pub=op_pub, runtime_pub=rp_pub,
        updated="2026-05-07T00:07:00Z",
    )
    out.append(vec(
        "178-manifest-updated-future-skew",
        kind="manifest",
        description=(
            "Manifest whose `updated` is set 6 minutes ahead of clock_now "
            "(2026-05-07T00:07:00Z vs 2026-05-07T00:01:00Z), exceeding "
            "the 300-second future-skew tolerance defined in §10. Per "
            "§06:342 and §10:815, this is rejected as "
            "E_SCHEMA_FIELD_SYNTAX with structured details "
            "reason=future_beyond_skew_tolerance. The manifest is signed "
            "correctly and otherwise valid; the temporal-domain failure "
            "is the only live violation at Stage 5."
        ),
        spec_refs=["§06", "§10", "§11"],
        verdict="reject",
        diagnostic="E_SCHEMA_FIELD_SYNTAX",
        diagnostic_details={"reason": "future_beyond_skew_tolerance"},
        body_obj=m_178,
        context={"fetched_origin_address": m_178["origin"]["address"]},
    ))

    # ---- 183-canary-issued-at-future-skew (Stage 8, E_CANARY_INVALID) ----
    # Manifest whose canary.issued_at is 6 minutes ahead of clock_now,
    # exceeding the 300-second future-skew tolerance defined in §10. Per
    # §08:68,156 this is one of the named E_CANARY_INVALID conditions
    # (issued_at implausibly in the future). The manifest signature is
    # valid and the canary interval falls within the 7-to-30-day bounds;
    # the only live violation at Stage 8 is the temporal-skew check.
    m_183 = make_manifest(
        publisher_priv=pp, publisher_pub=pp_pub,
        origin_pub=op_pub, runtime_pub=rp_pub,
        issued_at="2026-05-07T00:07:00Z",
        next_expected="2026-06-06T00:07:00Z",
        updated="2026-05-07T00:00:00Z",
    )
    out.append(vec(
        "183-canary-issued-at-future-skew",
        kind="manifest",
        description=(
            "Manifest whose canary.issued_at is 2026-05-07T00:07:00Z, 6 "
            "minutes ahead of clock_now (2026-05-07T00:01:00Z), "
            "exceeding the 300-second future-skew tolerance defined in "
            "§10. Per §08:68,156 this is one of the named "
            "E_CANARY_INVALID conditions. The manifest signature is "
            "valid, the canary interval is within bounds, and `updated` "
            "is kept at clock_now-1 to avoid competing with the §06 "
            "future-skew check exercised by vector 178: the Stage 8 "
            "issued_at check is the only live skew violation."
        ),
        spec_refs=["§08", "§10", "§11"],
        verdict="reject",
        diagnostic="E_CANARY_INVALID",
        body_obj=m_183,
        context={"fetched_origin_address": m_183["origin"]["address"]},
    ))

    # ---- 184-canary-runtime-reuse (Stage 8, E_CANARY_RUNTIME_REUSE) ----
    # Multi-manifest scenario: the previously verified manifest is dated
    # 2026-04-30 (carried in extra_files to avoid coupling to the 001
    # positive fixture and keep the live manifest at clock_now without
    # creating a future-skew confound). The presented manifest at
    # clock_now (issued_at 2026-05-07) declares the same runtime_pubkey
    # as the prior. Per §08 (rc.19 N55) and §11:200, rotation MUST
    # produce a distinct runtime_pubkey; reuse is rejected as
    # E_CANARY_RUNTIME_REUSE at Stage 8. Both the prior and the
    # presented manifest are signed correctly, are within canary
    # interval bounds, and have updated <= clock_now+300s so the only
    # live Stage 8 violation is the rotation-proof failure.
    m_184_prior = make_manifest(
        publisher_priv=pp, publisher_pub=pp_pub,
        origin_pub=op_pub, runtime_pub=rp_pub,
        issued_at="2026-04-30T00:00:00Z",
        next_expected="2026-05-30T00:00:00Z",
        updated="2026-04-30T00:00:00Z",
    )
    m_184_prior_bytes = json.dumps(
        m_184_prior, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    m_184 = make_manifest(
        publisher_priv=pp, publisher_pub=pp_pub,
        origin_pub=op_pub, runtime_pub=rp_pub,
        # default issued_at=2026-05-07, updated=2026-05-07; same runtime_pub
    )
    out.append(vec(
        "184-canary-runtime-reuse",
        kind="manifest",
        description=(
            "Multi-manifest scenario: a previously verified manifest "
            "dated 2026-04-30 (carried in extra_files as "
            "prior_manifest.json) authorizes runtime_pubkey X. The "
            "presented manifest at clock_now (issued_at 2026-05-07) for "
            "the same K_publisher.pub declares the same runtime_pubkey "
            "X. Per §08 (rc.19 N55) and §11:200, rotation MUST produce "
            "a distinct runtime_pubkey; reuse is rejected as "
            "E_CANARY_RUNTIME_REUSE at Stage 8. Both manifests are "
            "signed correctly and otherwise valid; the rotation-proof "
            "failure is the only live Stage 8 violation."
        ),
        spec_refs=["§08", "§11"],
        verdict="reject",
        diagnostic="E_CANARY_RUNTIME_REUSE",
        diagnostic_details={
            "runtime_pubkey": b64u(rp_pub),
            "previous_issued_at": "2026-04-30T00:00:00Z",
            "current_issued_at": "2026-05-07T00:00:00Z",
            "window_position": 1,
        },
        body_obj=m_184,
        context={
            "fetched_origin_address": m_184["origin"]["address"],
            "previously_verified": "vectors/184-canary-runtime-reuse/prior_manifest.json",
        },
        extra_files={
            "prior_manifest.json": m_184_prior_bytes,
        },
    ))

    # ---- 185-canary-runtime-reuse-resurrection (Stage 8,
    #      E_CANARY_RUNTIME_REUSE with window_position >= 2) ----
    #
    # Three-manifest A -> B -> A resurrection scenario. The publisher
    # history (carried in extra_files as prior_manifest_a.json and
    # prior_manifest_b.json) contains:
    #   M_A at issued_at 2026-04-23 with runtime_pubkey X (= rp_pub)
    #   M_B at issued_at 2026-04-30 with runtime_pubkey Y (= runtime_pub_2)
    # The presented manifest is M_C at issued_at 2026-05-07 with
    # runtime_pubkey X again (the rp_pub from M_A; not the immediately
    # preceding M_B's Y). Per §08 immediate-preceding MUST: M_C is
    # accepted at the MUST level because X != Y. Per §08 SHOULD for
    # clients maintaining runtime-pubkey history: M_C is rejected
    # because X is present in publisher history (M_A entry), with
    # E_CANARY_RUNTIME_REUSE.details.window_position = 2 (the match is
    # two entries back: M_A is two positions before M_C in the
    # ordered history M_A -> M_B -> M_C, i.e. M_A is the entry before
    # the immediately preceding M_B). Stateless clients accept M_C
    # (per §00 N60 limitation); stateful clients reject. This is the
    # canonical demonstration vector for the rc.19 N60 SHOULD.
    #
    # The corpus verdict records the stateful-client rejection
    # because that is the SHOULD path; stateless clients diverge by
    # design and a conformant stateless implementation reporting
    # accept on this vector is operating within the §00 N60
    # limitation. The vector's extended context field
    # `previously_verified_history` is a sequence of prior manifest
    # paths in publication order (oldest first) used by stateful
    # clients to populate their runtime-pubkey history before
    # presenting the vector input.
    m_185_a = make_manifest(
        publisher_priv=pp, publisher_pub=pp_pub,
        origin_pub=op_pub, runtime_pub=rp_pub,
        issued_at="2026-04-23T00:00:00Z",
        next_expected="2026-05-23T00:00:00Z",
        updated="2026-04-23T00:00:00Z",
    )
    m_185_a_bytes = json.dumps(
        m_185_a, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    m_185_b = make_manifest(
        publisher_priv=pp, publisher_pub=pp_pub,
        origin_pub=op_pub, runtime_pub=keys["runtime_pub_2"],
        issued_at="2026-04-30T00:00:00Z",
        next_expected="2026-05-30T00:00:00Z",
        updated="2026-04-30T00:00:00Z",
    )
    m_185_b_bytes = json.dumps(
        m_185_b, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    # Presented manifest M_C: resurrects runtime_pubkey X from M_A.
    # Default issued_at=2026-05-07 is strictly newer than M_B
    # 2026-04-30 so the immediate-preceding MUST passes (X != Y at
    # window_position=1); the SHOULD fires at window_position=2.
    m_185_c = make_manifest(
        publisher_priv=pp, publisher_pub=pp_pub,
        origin_pub=op_pub, runtime_pub=rp_pub,
    )
    out.append(vec(
        "185-canary-runtime-reuse-resurrection",
        kind="manifest",
        description=(
            "A -> B -> A resurrection scenario. The publisher history "
            "(extra_files) contains M_A (issued_at 2026-04-23, "
            "runtime_pubkey X) and M_B (issued_at 2026-04-30, "
            "runtime_pubkey Y). The presented manifest M_C at "
            "clock_now (issued_at 2026-05-07) declares runtime_pubkey "
            "X again, resurrecting the M_A key after M_B retired it. "
            "Per §08 immediate-preceding MUST, M_C passes (X != Y). "
            "Per §08 SHOULD for clients maintaining runtime-pubkey "
            "history, M_C is rejected as E_CANARY_RUNTIME_REUSE with "
            "details.window_position = 2 (M_A is two entries back). "
            "Stateless clients accept (per §00 N60 limitation); the "
            "corpus verdict records the stateful-client rejection."
        ),
        spec_refs=["§08", "§00", "§11"],
        verdict="reject",
        diagnostic="E_CANARY_RUNTIME_REUSE",
        diagnostic_details={
            "runtime_pubkey": b64u(rp_pub),
            "previous_issued_at": "2026-04-23T00:00:00Z",
            "current_issued_at": "2026-05-07T00:00:00Z",
            "window_position": 2,
        },
        body_obj=m_185_c,
        context={
            "fetched_origin_address": m_185_c["origin"]["address"],
            "previously_verified_history": [
                "vectors/185-canary-runtime-reuse-resurrection/prior_manifest_a.json",
                "vectors/185-canary-runtime-reuse-resurrection/prior_manifest_b.json",
            ],
        },
        extra_files={
            "prior_manifest_a.json": m_185_a_bytes,
            "prior_manifest_b.json": m_185_b_bytes,
        },
    ))

    # ---- 186-canary-malformed-timestamp (Stage 8, E_CANARY_INVALID; AMB-16) ----
    #
    # Manifest whose canary.next_expected is a syntactically malformed
    # timestamp ("garbage" -- a valid JSON string, but not the 20-char
    # RFC 3339 form). Per §08 the canary Invalid state explicitly includes
    # "invalid timestamp syntax", and AMB-16 (rc.32) pins this to Stage 8
    # E_CANARY_INVALID, not a generic Stage 5 schema code. The manifest is
    # signed correctly over the malformed-timestamp payload so the signature
    # verifies (Stage 6 passes) and the pipeline reaches Stage 8, where the
    # malformed canary timestamp is the only live violation. Distinct from
    # vector 182 (E_CANARY_INVALID for an interval-bound violation).
    m_186 = make_manifest(
        publisher_priv=pp, publisher_pub=pp_pub,
        origin_pub=op_pub, runtime_pub=rp_pub,
        next_expected="garbage",
    )
    out.append(vec(
        "186-canary-malformed-timestamp",
        kind="manifest",
        description=(
            "Manifest whose canary.next_expected is a syntactically "
            "malformed timestamp (\"garbage\", not the RFC 3339 20-char "
            "form). Per §08 the canary Invalid state includes invalid "
            "timestamp syntax; AMB-16 pins this to Stage 8 E_CANARY_INVALID, "
            "not a generic Stage 5 schema code. Signed correctly so Stage 6 "
            "passes and the pipeline reaches Stage 8, where the malformed "
            "canary timestamp is the only live violation. Distinct from "
            "vector 182 (interval-bound E_CANARY_INVALID)."
        ),
        spec_refs=["§08", "§11"],
        verdict="reject",
        diagnostic="E_CANARY_INVALID",
        body_obj=m_186,
        context={"fetched_origin_address": m_186["origin"]["address"]},
    ))

    # ---- 191-unicode-nfd-freshness-proof (Stage 5, E_SCHEMA_FIELD_SYNTAX) ----
    # Parity with vector 190 (statement NFD): manifest whose
    # canary.freshness_proof contains a decomposed combining mark
    # (NFD) rather than the precomposed NFC form. §04 plus the §08
    # explicit MUST NFC for freshness_proof (rc.19 N59) require the
    # field to be NFC. Rejected at schema validation with
    # E_SCHEMA_FIELD_SYNTAX before signature verification.
    # freshness_proof "Cafe(acute) block-871234" in NFD: "Cafe" + U+0301 + " block-871234"
    nfd_freshness = "Cafe\u0301 block-871234"
    m_191_payload = {
        "spec_version": "1.0",
        "kind": "manifest",
        "publisher_pubkey": b64u(pp_pub),
        "origin": {
            "carrier": "tor-v3",
            "address": onion_address(op_pub),
            "origin_pubkey": b64u(op_pub),
        },
        "canary": {
            "runtime_pubkey": b64u(rp_pub),
            "issued_at": "2026-05-07T00:00:00Z",
            "next_expected": "2026-06-06T00:00:00Z",
            "statement": "No warrants received.",
            "freshness_proof": nfd_freshness,
        },
        "state_policy": [],
        "navigation": [],
        "min_refresh_interval": 3600,
        "updated": "2026-05-07T00:00:00Z",
    }
    m_191_payload["sig"] = sign(pp, CTX_MANIFEST, m_191_payload)
    out.append(vec(
        "191-unicode-nfd-freshness-proof",
        kind="manifest",
        description="Manifest whose canary.freshness_proof contains a decomposed combining mark (NFD) rather than the precomposed NFC form. Per §04 and the §08 explicit NFC rule for freshness_proof (rc.19 N59), user-visible strings must be in NFC. Rejected at schema validation with E_SCHEMA_FIELD_SYNTAX before signature verification. Parity with vector 190 for canary.statement.",
        spec_refs=["§04", "§08"],
        verdict="reject",
        diagnostic="E_SCHEMA_FIELD_SYNTAX",
        body_obj=m_191_payload,
        context={"fetched_origin_address": m_191_payload["origin"]["address"]},
    ))

    # ---- 192-unicode-nfd-submit-label (Stage 5, E_SCHEMA_FIELD_SYNTAX) ----
    # Content document with a submit_form whose submit_label is in NFD
    # ("Cafe" + U+0301 combining acute) rather than precomposed NFC. Per
    # §04:159 the submit_form form-level labels are user-visible and MUST be
    # NFC; a non-NFC value is rejected at schema validation with
    # E_SCHEMA_FIELD_SYNTAX before signature verification (§04:167, §10).
    # Every other field is valid and NFC, so the NFD submit_label is the only
    # live Stage 5 violation.
    c_nfd_submit_label = make_content(
        runtime_priv=rp,
        path="/contact-form",
        title="Contact",
        blocks=[{
            "kind": "submit_form",
            "label": [
                {"kind": "text", "value": "Contact us", "marks": []},
            ],
            "submit_to": "/contact",
            "fields": [
                {
                    "kind": "textarea",
                    "name": "message",
                    "label": "Message",
                    "required": True,
                    "max_length": 1000,
                }
            ],
            "submit_label": "Café",  # NFD: "Cafe" + U+0301 combining acute
        }],
    )
    out.append(vec(
        "192-unicode-nfd-submit-label",
        kind="content",
        description="Content document whose submit_form.submit_label is in NFD (\"Cafe\" + U+0301 combining acute) rather than the precomposed NFC form. Per §04:159 the submit_form form-level labels are user-visible and MUST be NFC; a non-NFC value is rejected at schema validation with E_SCHEMA_FIELD_SYNTAX before signature verification. Every other field is valid and NFC, so the NFD submit_label is the only live Stage 5 violation.",
        spec_refs=["§03", "§04"],
        verdict="reject",
        diagnostic="E_SCHEMA_FIELD_SYNTAX",
        body_obj=c_nfd_submit_label,
        context={
            "fetched_path": c_nfd_submit_label["path"],
            "expected_runtime_pubkey": b64u(rp_pub),
        },
    ))

    # ---- 201-migration-chain-cycle (E_MIGRATION_INVALID chain_cycle) ----
    #
    # Two-manifest scenario realizing the deterministic A -> B -> A chain
    # cycle. The announcing manifest at origin A (op_pub) carries a
    # migration_pointer to successor B (op_pub_2). The successor manifest
    # at B is signed correctly and binds correctly, but its own
    # migration_pointer announces a return to A (op_pub). Per §10:436,
    # the visited_origins set populated during a single migration
    # resolution flow forbids re-adopting an address already in the set;
    # B's announcement of A is therefore rejected as E_MIGRATION_INVALID
    # with details.reason="chain_cycle". The diagnostic is deterministic
    # across conforming clients: any client tracking visited_origins per
    # §10 will reject on the second hop regardless of chain-depth policy.
    # The vector pairs the announcing manifest at A as the primary input;
    # the successor manifest at B is provided in extra_files. The verdict
    # refers to the migration adoption outcome, not the in-isolation
    # validity of the announcing manifest.
    op_pub_2_201 = keys["origin_pub_2"]
    address_a = onion_address(op_pub)
    address_b = onion_address(op_pub_2_201)
    successor_b = make_manifest(
        publisher_priv=pp, publisher_pub=pp_pub,
        origin_pub=op_pub_2_201, runtime_pub=rp_pub,
        migration_pointer={
            "successor_origin": {
                "carrier": "tor-v3",
                "address": address_a,  # back to A
                "origin_pubkey": b64u(op_pub),
            },
            "announced_at": "2026-05-07T00:00:00Z",
        },
    )
    successor_b_bytes = json.dumps(
        successor_b, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    announcing_a = make_manifest(
        publisher_priv=pp, publisher_pub=pp_pub,
        origin_pub=op_pub, runtime_pub=rp_pub,
        migration_pointer={
            "successor_origin": {
                "carrier": "tor-v3",
                "address": address_b,
                "origin_pubkey": b64u(op_pub_2_201),
            },
            "announced_at": "2026-05-07T00:00:00Z",
        },
    )
    out.append(vec(
        "201-migration-chain-cycle",
        kind="manifest",
        description=(
            "Two-manifest chain-cycle scenario A -> B -> A. The "
            "announcing manifest at origin A carries a migration_pointer "
            "to successor B (op_pub_2). The successor at B is signed "
            "correctly and binds correctly, but its own "
            "migration_pointer announces a return to A. Per §10:436, "
            "the per-flow visited_origins set forbids re-adopting an "
            "address already visited; B's announcement of A is rejected "
            "as E_MIGRATION_INVALID with details.reason='chain_cycle'. "
            "The diagnostic is deterministic across conforming clients "
            "(any client tracking visited_origins per §10 rejects on "
            "the second hop, regardless of chain-depth policy)."
        ),
        spec_refs=["§06", "§10", "§11"],
        verdict="reject",
        diagnostic="E_MIGRATION_INVALID",
        diagnostic_details={
            "reason": "chain_cycle",
            "announcing_origin_address": address_b,
            "successor_origin_address": address_a,
        },
        body_obj=announcing_a,
        context={
            "fetched_origin_address": address_a,
            "successor_origin_address": address_b,
            "successor_manifest_path": "vectors/201-migration-chain-cycle/successor_manifest.json",
        },
        extra_files={
            "successor_manifest.json": successor_b_bytes,
        },
    ))

    # ---- 202-migration-successor-key-mismatch (E_MIGRATION_INVALID
    #      successor_key_mismatch) ----
    #
    # Single-manifest, announcement-internal check (§06). The announcing
    # manifest at origin A (op_pub) carries a migration_pointer whose
    # successor_origin.address is the onion address of op_pub_2 but whose
    # declared origin_pubkey is op_pub. For Tor v3 the address decodes to a
    # public key (op_pub_2) that does not equal the declared origin_pubkey
    # (op_pub), violating the §06 address-to-key binding for the successor
    # pointer. This is evaluated when the announcing manifest is validated;
    # it does not require fetching the successor (distinct from the §10
    # fetch-time E_MIGRATION_MISMATCH checks). Rejected as
    # E_MIGRATION_INVALID with details.reason="successor_key_mismatch".
    address_a_202 = onion_address(op_pub)
    address_b_202 = onion_address(op_pub_2)
    announcing_202 = make_manifest(
        publisher_priv=pp, publisher_pub=pp_pub,
        origin_pub=op_pub, runtime_pub=rp_pub,
        migration_pointer={
            "successor_origin": {
                "carrier": "tor-v3",
                "address": address_b_202,       # decodes to op_pub_2
                "origin_pubkey": b64u(op_pub),  # but declares op_pub
            },
            "announced_at": "2026-05-07T00:00:00Z",
        },
    )
    out.append(vec(
        "202-migration-successor-key-mismatch",
        kind="manifest",
        description=(
            "Announcement-internal successor binding failure (§06). The "
            "migration_pointer.successor_origin.address decodes to op_pub_2 "
            "but the declared successor_origin.origin_pubkey is op_pub, so "
            "the address does not decode to the declared key. Per §06 the "
            "client MUST verify this binding before treating the "
            "announcement as valid; failure is E_MIGRATION_INVALID with "
            "details.reason='successor_key_mismatch'. The check is "
            "evaluated on the announcing manifest alone and does not fetch "
            "the successor (distinct from the §10 fetch-time "
            "E_MIGRATION_MISMATCH path)."
        ),
        spec_refs=["§05", "§06", "§11"],
        verdict="reject",
        diagnostic="E_MIGRATION_INVALID",
        diagnostic_details={
            "reason": "successor_key_mismatch",
            "announcing_origin_address": address_a_202,
            "successor_origin_address": address_b_202,
        },
        body_obj=announcing_202,
        context={
            "fetched_origin_address": address_a_202,
        },
    ))

    # ---- 203-migration-self-pointer-precedence (AMB-19) ----
    #
    # Pins the pipeline stage of the announcement-internal migration_pointer
    # self_pointer check. The announcing manifest declares a migration_pointer
    # whose successor_origin.address equals its own origin.address (a
    # self_pointer) and is ALSO tampered after signing so its Stage 6 signature
    # no longer verifies. Two readings placed the self_pointer check at
    # different stages: Stage 5 (a closed-schema cross-field check on the
    # announcing manifest, in the class of E_ORIGIN_INVALID) or Stage 9 (with
    # the rest of migration binding). Under §10 first-failing-stage precedence
    # the readings report different codes for identical wire bytes: Stage 5
    # reports E_MIGRATION_INVALID (reason self_pointer) before the Stage 6
    # signature failure; a Stage 9 reading would report the Stage 6
    # E_SIG_VERIFICATION first and never reach the self_pointer check. AMB-19
    # pins Stage 5 (consistent with E_ORIGIN_INVALID, AMB-05), so the expected
    # diagnostic is E_MIGRATION_INVALID with details.reason="self_pointer".
    # carrier matches and origin_pubkey decodes from the address, and
    # announced_at equals (not after) updated, so self_pointer is the only live
    # migration semantic violation.
    self_addr = onion_address(op_pub)
    m_selfptr = make_manifest(
        publisher_priv=pp, publisher_pub=pp_pub,
        origin_pub=op_pub, runtime_pub=rp_pub,
        migration_pointer={
            "successor_origin": {
                "carrier": "tor-v3",
                "address": self_addr,            # equals origin.address
                "origin_pubkey": b64u(op_pub),   # equals origin.origin_pubkey
            },
            "announced_at": "2026-05-07T00:00:00Z",
        },
    )
    # Tamper a non-sig field after signing so the Stage 6 signature no longer
    # verifies, giving a co-occurring later-stage failure. The Stage 5
    # self_pointer check must still be the reported diagnostic.
    m_selfptr["min_refresh_interval"] = m_selfptr["min_refresh_interval"] + 1
    out.append(vec(
        "203-migration-self-pointer-precedence",
        kind="manifest",
        description=(
            "Announcement-internal migration_pointer self_pointer "
            "(successor_origin.address equals origin.address) co-occurring with "
            "a Stage 6 signature failure (a non-sig field was changed after "
            "signing). AMB-19 pins the four announcement-internal "
            "E_MIGRATION_INVALID reasons (self_pointer, carrier_mismatch, "
            "announced_at_after_updated, successor_key_mismatch) to Stage 5 "
            "closed-schema validation, the same class as E_ORIGIN_INVALID "
            "(AMB-05); only chain_cycle is Stage 9. Under §10 "
            "first-failing-stage precedence the Stage 5 self_pointer is "
            "reported before the Stage 6 signature failure, so the diagnostic "
            "is E_MIGRATION_INVALID with details.reason=\"self_pointer\", not "
            "E_SIG_VERIFICATION. This pins the stage cross-implementation: a "
            "Stage 9 reading would report E_SIG_VERIFICATION instead."
        ),
        spec_refs=["§06", "§10", "§11"],
        verdict="reject",
        diagnostic="E_MIGRATION_INVALID",
        diagnostic_details={
            "reason": "self_pointer",
            "announcing_origin_address": self_addr,
            "successor_origin_address": self_addr,
        },
        body_obj=m_selfptr,
        context={"fetched_origin_address": self_addr},
    ))

    # ---- 204-migration-broken-successor-reverse-cycle (AMB-26) ----
    #
    # Announcing manifest A points to successor B. B fails its OWN pipeline
    # (origin.not_after in the past at clock_now -> E_ORIGIN_EXPIRED) AND
    # announces a migration_pointer back to A (a reverse A->B->A cycle). Per
    # §10:398-405 the successor's own onward announcement (its second-hop
    # chain_cycle) is processed only after B passes its full pipeline and the
    # publisher/binding continuity checks; a broken B therefore surfaces
    # E_MIGRATION_MISMATCH (mismatch_field=successor_stage9_failure, underlying
    # E_ORIGIN_EXPIRED) first, NOT chain_cycle. This pins the ordering
    # cross-implementation: a reading that peeks the successor's onward
    # migration_pointer before verifying the successor would report
    # E_MIGRATION_INVALID/chain_cycle instead.
    announcing_addr_204 = onion_address(op_pub)
    successor_addr_204 = onion_address(op_pub_2)
    successor_204 = make_manifest(
        publisher_priv=pp, publisher_pub=pp_pub,
        origin_pub=op_pub_2, runtime_pub=rp_pub,
        issued_at="2026-04-01T00:00:00Z",
        next_expected="2026-05-01T00:00:00Z",
        updated="2026-04-01T00:00:00Z",
        not_after="2026-05-01T00:00:00Z",  # past relative to clock_now -> E_ORIGIN_EXPIRED
        migration_pointer={
            "successor_origin": {
                "carrier": "tor-v3",
                "address": announcing_addr_204,    # back-pointer to A (reverse cycle)
                "origin_pubkey": b64u(op_pub),
            },
            "announced_at": "2026-04-01T00:00:00Z",
        },
    )
    successor_204_bytes = json.dumps(
        successor_204, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    announcing_204 = make_manifest(
        publisher_priv=pp, publisher_pub=pp_pub,
        origin_pub=op_pub, runtime_pub=rp_pub,
        migration_pointer={
            "successor_origin": {
                "carrier": "tor-v3",
                "address": successor_addr_204,
                "origin_pubkey": b64u(op_pub_2),
            },
            "announced_at": "2026-05-07T00:00:00Z",
        },
    )
    out.append(vec(
        "204-migration-broken-successor-reverse-cycle",
        kind="manifest",
        description=(
            "Migration scenario pinning the ordering of the successor's own "
            "chain_cycle relative to successor verification (AMB-26). The "
            "announcing manifest A points to successor B; the successor manifest "
            "(extra_files/successor_manifest.json) fails its own Stage 9 with "
            "E_ORIGIN_EXPIRED (origin.not_after 2026-05-01 is past clock_now "
            "2026-05-07) AND carries a migration_pointer back to A (a reverse "
            "A->B->A cycle). Per §10:398-405 the successor's onward announcement "
            "is processed only after the successor passes its full pipeline and "
            "the publisher/binding continuity checks, so a broken successor is "
            "reported as E_MIGRATION_MISMATCH (mismatch_field="
            "'successor_stage9_failure', underlying_diagnostic_code="
            "'E_ORIGIN_EXPIRED'), not E_MIGRATION_INVALID/chain_cycle. Pairs with "
            "200 (broken successor, no back-pointer) and 201 (valid successor "
            "with back-pointer -> chain_cycle)."
        ),
        spec_refs=["§06", "§10", "§11"],
        verdict="reject",
        diagnostic="E_MIGRATION_MISMATCH",
        diagnostic_details={
            "mismatch_field": "successor_stage9_failure",
            "underlying_diagnostic_code": "E_ORIGIN_EXPIRED",
        },
        body_obj=announcing_204,
        context={
            "fetched_origin_address": announcing_204["origin"]["address"],
            "successor_origin_address": successor_addr_204,
            "successor_manifest_path": "vectors/204-migration-broken-successor-reverse-cycle/successor_manifest.json",
        },
        extra_files={
            "successor_manifest.json": successor_204_bytes,
        },
    ))

    return out


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    # Reset the vectors directory so generation is fresh and reproducible.
    if VECTORS_DIR.exists():
        shutil.rmtree(VECTORS_DIR)
    VECTORS_DIR.mkdir(parents=True)

    publisher_priv, publisher_pub = keypair(PUBLISHER_SEED)
    runtime_priv, runtime_pub = keypair(RUNTIME_SEED)
    origin_priv, origin_pub = keypair(ORIGIN_SEED)
    runtime_priv_2, runtime_pub_2 = keypair(RUNTIME_SEED_2)
    origin_priv_2, origin_pub_2 = keypair(ORIGIN_SEED_2)

    keys = {
        "publisher_priv": publisher_priv,
        "publisher_pub": publisher_pub,
        "runtime_priv": runtime_priv,
        "runtime_pub": runtime_pub,
        "origin_priv": origin_priv,
        "origin_pub": origin_pub,
        "runtime_priv_2": runtime_priv_2,
        "runtime_pub_2": runtime_pub_2,
        "origin_priv_2": origin_priv_2,
        "origin_pub_2": origin_pub_2,
    }

    wordlist = load_bip39_wordlist()
    publisher_entry = {
        "seed_hex": PUBLISHER_SEED.hex(),
        "pub_b64u": b64u(publisher_pub),
    }
    if wordlist is not None:
        publisher_entry["pip"] = compute_pip(publisher_pub, wordlist)

    keys_doc = {
        "_comment": "Test fixtures only. NEVER use these for any real deployment.",
        "publisher": publisher_entry,
        "runtime": {
            "seed_hex": RUNTIME_SEED.hex(),
            "pub_b64u": b64u(runtime_pub),
        },
        "origin": {
            "seed_hex": ORIGIN_SEED.hex(),
            "pub_b64u": b64u(origin_pub),
            "tor_v3_address": onion_address(origin_pub),
        },
        "runtime_2": {
            "seed_hex": RUNTIME_SEED_2.hex(),
            "pub_b64u": b64u(runtime_pub_2),
        },
        "origin_2": {
            "seed_hex": ORIGIN_SEED_2.hex(),
            "pub_b64u": b64u(origin_pub_2),
            "tor_v3_address": onion_address(origin_pub_2),
        },
    }
    (ROOT / "keys.json").write_bytes(
        (json.dumps(keys_doc, indent=2, ensure_ascii=False) + "\n")
        .encode("utf-8")
    )

    vectors: list[dict] = []
    vectors.extend(positive_vectors(keys))
    vectors.extend(negative_vectors(keys))

    corpus = {
        "_comment": "Generated by corpus/tools/generate.py. Do not hand-edit.",
        "spec_version_target": "1.0",
        "rc_target": "1.0-rc.44",
        "keys": "keys.json",
        "clock_now": "2026-05-07T00:01:00Z",
        "vectors": vectors,
    }
    (ROOT / "corpus.json").write_bytes(
        (json.dumps(corpus, indent=2, ensure_ascii=False) + "\n")
        .encode("utf-8")
    )

    print(f"Generated {len(vectors)} vectors -> {VECTORS_DIR}")
    print(f"  positive: {sum(1 for v in vectors if v['expected']['verdict'] == 'accept')}")
    print(f"  negative: {sum(1 for v in vectors if v['expected']['verdict'] == 'reject')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
