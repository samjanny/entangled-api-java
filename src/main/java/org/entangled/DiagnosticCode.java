package org.entangled;

/**
 * The normative diagnostic codes from specification section 11.
 *
 * <p>Each constant carries its normative {@code severity} and the pipeline
 * {@code stage} (1 through 10) at which it is detected, as defined in section 11
 * and section 10. Codes that do not map to a pipeline stage use {@code stage 0}.
 *
 * <p>Only the codes reachable by this implementation are enumerated here; the
 * full catalog is larger (transport, image, and several state/historical codes
 * are not wire-constructible within the corpus scope, per corpus/README.md).
 * Codes that are part of the catalog but not yet exercised are still listed so
 * the enum mirrors section 11 faithfully.
 */
public enum DiagnosticCode {

    // --- Transport diagnostics (Stage 1) ---
    E_TRANSPORT_STATUS(Severity.ERROR, 1),
    E_TRANSPORT_REDIRECT(Severity.ERROR, 1),
    E_TRANSPORT_CONTENT_TYPE(Severity.ERROR, 1),
    E_TRANSPORT_CONTENT_LENGTH(Severity.ERROR, 1),
    E_TRANSPORT_BODY_FAILURE(Severity.ERROR, 1),
    E_TRANSPORT_RATE_LIMITED(Severity.ERROR, 1),
    E_TRANSPORT_NOT_FOUND(Severity.ERROR, 1),
    E_TRANSPORT_METHOD_NOT_ALLOWED(Severity.ERROR, 1),
    E_TRANSPORT_PAYLOAD_TOO_LARGE(Severity.ERROR, 1),
    E_TRANSPORT_UNAVAILABLE(Severity.ERROR, 1),
    E_TRANSPORT_BAD_REQUEST(Severity.ERROR, 1),
    E_TRANSPORT_CONTENT_ENCODING(Severity.ERROR, 1),
    E_TRANSPORT_TRANSFER_ENCODING(Severity.ERROR, 1),

    // --- Input diagnostics (Stage 2) ---
    E_INPUT_BYTE_CAP(Severity.ERROR, 2),
    E_INPUT_UTF8(Severity.ERROR, 2),
    E_INPUT_BOM(Severity.ERROR, 2),

    // --- Parsing diagnostics (Stage 3) ---
    E_PARSE_JSON(Severity.ERROR, 3),
    E_PARSE_NESTING_DEPTH(Severity.ERROR, 3),
    E_PARSE_STRING_LENGTH(Severity.ERROR, 3),
    E_PARSE_ARRAY_LENGTH(Severity.ERROR, 3),
    E_PARSE_OBJECT_KEYS(Severity.ERROR, 3),
    E_PARSE_DUPLICATE_KEY(Severity.ERROR, 3),

    // --- Document kind diagnostics (Stage 4) ---
    E_KIND_MISSING_FIELDS(Severity.ERROR, 4),
    E_KIND_SPEC_VERSION(Severity.ERROR, 4),
    E_KIND_UNKNOWN(Severity.ERROR, 4),

    // --- Schema diagnostics (Stage 5) ---
    E_SCHEMA_REQUIRED_FIELD(Severity.ERROR, 5),
    E_SCHEMA_UNKNOWN_FIELD(Severity.ERROR, 5),
    E_SCHEMA_BLOCK_NOT_PERMITTED(Severity.ERROR, 5),
    E_SCHEMA_FIELD_TYPE(Severity.ERROR, 5),
    E_SCHEMA_FIELD_RANGE(Severity.ERROR, 5),
    E_SCHEMA_FIELD_SYNTAX(Severity.ERROR, 5),
    E_SCHEMA_ENUM_VIOLATION(Severity.ERROR, 5),
    E_SCHEMA_DUPLICATE_ENTRY(Severity.ERROR, 5),
    E_SCHEMA_FIELD_LENGTH(Severity.ERROR, 5),
    E_SCHEMA_NULL_VALUE(Severity.ERROR, 5),
    E_SCHEMA_NON_INTEGER(Severity.ERROR, 5),
    E_SCHEMA_MALFORMED_UNICODE(Severity.ERROR, 5),
    E_SUBMIT_BUDGET(Severity.ERROR, 5),
    E_ORIGIN_INVALID(Severity.ERROR, 5),

    // --- Signature diagnostics (Stage 6) ---
    E_SIG_VERIFICATION(Severity.ERROR, 6),
    E_SIG_INVALID_KEY(Severity.ERROR, 6),
    E_SIG_MALFORMED(Severity.ERROR, 6),

    // --- Trust state diagnostics (Stage 6 pre-check and Stage 7) ---
    E_TRUST_MISMATCH(Severity.ERROR, 6),
    E_TRUST_USER_REJECTED(Severity.ERROR, 6),
    I_TRUST_FIRST_CONTACT(Severity.INFO, 7),
    I_TRUST_TOFU_PINNED(Severity.INFO, 7),
    I_TRUST_VERIFIED(Severity.INFO, 7),

    // --- Canary diagnostics (Stage 8) ---
    E_CANARY_INVALID(Severity.ERROR, 8),
    E_CANARY_DOWNGRADE(Severity.ERROR, 8),
    E_CANARY_CONFLICT(Severity.ERROR, 8),
    W_CANARY_NEAR_EXPIRATION(Severity.WARNING, 8),
    E_CANARY_EXPIRED(Severity.ERROR, 8),
    W_CANARY_GAP(Severity.WARNING, 8),
    W_CANARY_UNAVAILABLE(Severity.WARNING, 8),
    E_CANARY_RUNTIME_REUSE(Severity.ERROR, 8),

    // --- Binding diagnostics (Stage 9) ---
    E_BIND_PATH(Severity.ERROR, 9),
    E_BIND_RESPONSE_PATH(Severity.ERROR, 9),
    E_BIND_REQUEST_ID(Severity.ERROR, 9),
    E_BIND_REQUEST_HASH(Severity.ERROR, 9),
    E_BIND_ORIGIN(Severity.ERROR, 9),
    E_ORIGIN_EXPIRED(Severity.ERROR, 9),
    E_MIGRATION_MISMATCH(Severity.ERROR, 9),
    E_MIGRATION_INVALID(Severity.ERROR, 9),
    E_CONTENT_INDEX_FETCH_FAILED(Severity.ERROR, 9),
    E_CONTENT_INDEX_HASH_MISMATCH(Severity.ERROR, 9),
    E_CONTENT_INDEX_INVALID(Severity.ERROR, 9),
    E_CONTENT_SEQ_MISSING(Severity.ERROR, 9),
    E_CONTENT_SEQ_ROLLBACK(Severity.ERROR, 9),
    E_CONTENT_SEQ_UNCOMMITTED(Severity.ERROR, 9),
    E_CONTENT_HASH_MISMATCH(Severity.ERROR, 9),

    // --- State diagnostics ---
    E_STATE_UNDECLARED(Severity.ERROR, 0),
    E_STATE_VALUE_SIZE(Severity.ERROR, 0),
    E_STATE_TTL(Severity.ERROR, 0),
    E_STATE_OP(Severity.ERROR, 0),
    E_STATE_STORAGE_CAP(Severity.ERROR, 0),
    E_STATE_TRANSMIT_BUDGET(Severity.ERROR, 0),
    E_STATE_DUPLICATE(Severity.ERROR, 0),

    // --- Historical content diagnostics ---
    E_HISTORICAL_NO_AUTHORIZATION(Severity.ERROR, 0),
    E_HISTORICAL_NO_PUBLICATION_PROOF(Severity.ERROR, 0),
    E_HISTORICAL_TRUST_BLOCKED(Severity.ERROR, 0),
    E_HISTORICAL_RUNTIME_AMBIGUOUS(Severity.ERROR, 0);

    /** Severity classes from section 11. */
    public enum Severity { ERROR, WARNING, INFO }

    private final Severity severity;
    private final int stage;

    DiagnosticCode(Severity severity, int stage) {
        this.severity = severity;
        this.stage = stage;
    }

    public Severity severity() {
        return severity;
    }

    public int stage() {
        return stage;
    }
}
