package org.entangled.pipeline;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import org.entangled.DiagnosticCode;
import org.entangled.RejectException;
import org.entangled.crypto.Base64Url;
import org.entangled.crypto.Sha;
import org.entangled.json.JsonParser;
import org.entangled.json.JsonValue;
import org.entangled.schema.Fields;
import org.entangled.schema.Paths;

/**
 * Stage 9b: content index and content sequencing (section 02, section 06,
 * section 09, section 10).
 *
 * <p>A manifest may carry {@code content_root}, the SHA-256 of the exact bytes
 * of {@code /content_index.json}. The index is a closed-structure document
 * {@code {"entries": {"/path": {"seq": N, "hash": "sha-256:..."}}}}; it is not a
 * signed Entangled document. When a manifest declares {@code content_root} the
 * client fetches and hash-checks the served index against it, structurally
 * validates it, and then, for a content document being rendered, compares the
 * document's {@code seq} and response-body hash against the committed entry for
 * its path.
 *
 * <p>{@code E_CONTENT_INDEX_FETCH_FAILED} (a transport failure of the index
 * fetch) is not exercised here; the corpus carries the served index bytes
 * directly.
 */
public final class Stage9ContentIndex {

    /** Response-body cap for the content index (section 09). */
    private static final int INDEX_MAX_BYTES = 1024 * 1024;

    private Stage9ContentIndex() {
    }

    /**
     * Verify a manifest's declared {@code content_root} against the served index
     * bytes and structurally validate the index. No-op when the manifest does
     * not declare {@code content_root}.
     *
     * @param manifest    the parsed manifest document
     * @param indexBytes  the exact bytes of the served {@code /content_index.json},
     *                    or null when none was supplied
     */
    public static void verifyManifestIndex(JsonValue.Obj manifest, byte[] indexBytes) {
        if (!(manifest.get("content_root") instanceof JsonValue.Str rootStr)) {
            return; // manifest declares no content_root; Stage 9b does not apply.
        }
        if (indexBytes == null) {
            // Manifest commits to an index but none was provided. A real client
            // reaches this only on a transport failure of the index fetch.
            throw new RejectException(DiagnosticCode.E_CONTENT_INDEX_FETCH_FAILED);
        }
        parseVerifiedIndex(rootStr.value(), indexBytes);
    }

    /**
     * Verify a content document against the committed index entry for its path.
     * No-op when no content_root/index is supplied for this document.
     *
     * @param content      the parsed content document
     * @param body         the exact response-body bytes of the content document
     * @param contentRoot  the manifest's declared content_root (sha-256:...),
     *                     or null when none is supplied
     * @param indexBytes   the served index bytes, or null
     */
    public static void verifyContentSeq(
            JsonValue.Obj content, byte[] body, String contentRoot, byte[] indexBytes) {
        if (contentRoot == null) {
            return; // no verified content index applies to this document.
        }
        if (indexBytes == null) {
            throw new RejectException(DiagnosticCode.E_CONTENT_INDEX_FETCH_FAILED);
        }
        Map<String, IndexEntry> entries = parseVerifiedIndex(contentRoot, indexBytes);

        String path = Fields.str(content.get("path"));
        IndexEntry entry = entries.get(path);
        if (entry == null) {
            return; // path not indexed: protected only by the runtime signature.
        }

        if (!(content.get("seq") instanceof JsonValue.Num)) {
            throw new RejectException(DiagnosticCode.E_CONTENT_SEQ_MISSING);
        }
        long docSeq = Fields.integer(content.get("seq")).longValueExact();
        if (docSeq < entry.seq) {
            throw new RejectException(DiagnosticCode.E_CONTENT_SEQ_ROLLBACK);
        }
        if (docSeq > entry.seq) {
            throw new RejectException(DiagnosticCode.E_CONTENT_SEQ_UNCOMMITTED);
        }
        byte[] bodyHash = Sha.sha256(body);
        if (!Arrays.equals(bodyHash, entry.hash)) {
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("expected", entry.hashString);
            throw new RejectException(DiagnosticCode.E_CONTENT_HASH_MISMATCH, details);
        }
    }

    /**
     * Hash-check the index bytes against {@code contentRoot}, then parse and
     * structurally validate the index, returning its entries.
     */
    private static Map<String, IndexEntry> parseVerifiedIndex(String contentRoot, byte[] indexBytes) {
        byte[] rootBytes = decodeSha256(contentRoot, DiagnosticCode.E_CONTENT_INDEX_INVALID);
        if (indexBytes.length > INDEX_MAX_BYTES) {
            throw new RejectException(DiagnosticCode.E_CONTENT_INDEX_INVALID);
        }
        if (!Arrays.equals(Sha.sha256(indexBytes), rootBytes)) {
            throw new RejectException(DiagnosticCode.E_CONTENT_INDEX_HASH_MISMATCH);
        }
        return parseIndexStructure(decodeStrictUtf8(indexBytes));
    }

    /** Parse and structurally validate the closed index schema. */
    private static Map<String, IndexEntry> parseIndexStructure(String indexText) {
        JsonValue parsed;
        try {
            parsed = JsonParser.parse(indexText);
        } catch (RuntimeException e) {
            throw new RejectException(DiagnosticCode.E_CONTENT_INDEX_INVALID);
        }
        if (!(parsed instanceof JsonValue.Obj root)
                || root.members().size() != 1
                || !(root.get("entries") instanceof JsonValue.Obj entriesObj)) {
            throw new RejectException(DiagnosticCode.E_CONTENT_INDEX_INVALID);
        }
        Map<String, IndexEntry> out = new LinkedHashMap<>();
        for (Map.Entry<String, JsonValue> e : entriesObj.members().entrySet()) {
            if (!Paths.isValidContentPath(e.getKey())
                    || !(e.getValue() instanceof JsonValue.Obj entry)
                    || entry.members().size() != 2
                    || !(entry.get("seq") instanceof JsonValue.Num)
                    || !(entry.get("hash") instanceof JsonValue.Str hashStr)) {
                throw new RejectException(DiagnosticCode.E_CONTENT_INDEX_INVALID);
            }
            BigInteger seq = Fields.integer(entry.get("seq"));
            if (seq.signum() <= 0) {
                throw new RejectException(DiagnosticCode.E_CONTENT_INDEX_INVALID);
            }
            byte[] hash = decodeSha256(hashStr.value(), DiagnosticCode.E_CONTENT_INDEX_INVALID);
            out.put(e.getKey(), new IndexEntry(seq.longValueExact(), hash, hashStr.value()));
        }
        return out;
    }

    /** Decode index bytes as strict UTF-8 and reject a leading UTF-8 BOM. */
    private static String decodeStrictUtf8(byte[] bytes) {
        if (bytes.length >= 3
                && (bytes[0] & 0xff) == 0xef
                && (bytes[1] & 0xff) == 0xbb
                && (bytes[2] & 0xff) == 0xbf) {
            throw new RejectException(DiagnosticCode.E_CONTENT_INDEX_INVALID);
        }
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes))
                    .toString();
        } catch (CharacterCodingException e) {
            throw new RejectException(DiagnosticCode.E_CONTENT_INDEX_INVALID);
        }
    }

    /** Decode a {@code sha-256:<base64url>} field to its 32 raw bytes. */
    private static byte[] decodeSha256(String s, DiagnosticCode onError) {
        if (s.length() != 51 || !s.startsWith("sha-256:")) {
            throw new RejectException(onError);
        }
        try {
            return Base64Url.decode(s.substring("sha-256:".length()), 32);
        } catch (RuntimeException e) {
            throw new RejectException(onError);
        }
    }

    private record IndexEntry(long seq, byte[] hash, String hashString) {
    }
}
