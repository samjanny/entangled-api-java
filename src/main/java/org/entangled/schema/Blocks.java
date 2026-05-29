package org.entangled.schema;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.entangled.DiagnosticCode;
import org.entangled.RejectException;
import org.entangled.json.JsonValue;

/**
 * Block-grammar validation for the eleven block kinds, section 03.
 *
 * <p>Each block is validated against the closed schema for its declared
 * {@code kind}; an unknown kind is {@code E_SCHEMA_ENUM_VIOLATION}. A
 * {@code submit_form} block in a transaction document is
 * {@code E_SCHEMA_BLOCK_NOT_PERMITTED}. Inline content is validated by
 * {@link Inline}; per-block aggregate byte caps are enforced here.
 */
public final class Blocks {

    private static final Set<String> KNOWN_KINDS = Set.of(
            "paragraph", "heading", "code_block", "quote", "list", "divider",
            "image", "link", "submit_form", "feedback", "note");

    private static final Set<String> FEEDBACK_VARIANTS = Set.of("success", "info", "warning", "error");
    private static final Set<String> NOTE_VARIANTS = Set.of("info", "warning", "danger", "success");
    private static final Set<String> MEDIA_TYPES = Set.of("image/png", "image/jpeg", "image/webp");
    private static final Set<String> FIELD_KINDS = Set.of("text", "textarea", "select", "checkbox");

    private Blocks() {
    }

    /** Validate one block. {@code transaction} selects document-kind permission rules. */
    public static void validate(JsonValue blockValue, boolean transaction) {
        JsonValue.Obj b = Fields.obj(blockValue);
        String kind = Fields.str(Inline.require(b, "kind"));
        if (!KNOWN_KINDS.contains(kind)) {
            throw new RejectException(DiagnosticCode.E_SCHEMA_ENUM_VIOLATION);
        }
        if (transaction && kind.equals("submit_form")) {
            throw new RejectException(DiagnosticCode.E_SCHEMA_BLOCK_NOT_PERMITTED);
        }
        switch (kind) {
            case "paragraph" -> paragraph(b);
            case "heading" -> heading(b);
            case "code_block" -> codeBlock(b);
            case "quote" -> quote(b);
            case "list" -> list(b);
            case "divider" -> divider(b);
            case "image" -> image(b);
            case "link" -> link(b);
            case "submit_form" -> submitForm(b);
            case "feedback" -> feedback(b);
            case "note" -> note(b);
            default -> throw new RejectException(DiagnosticCode.E_SCHEMA_ENUM_VIOLATION);
        }
    }

    private static void paragraph(JsonValue.Obj b) {
        Closed.check(b, Set.of("kind", "content"), Set.of("kind", "content"));
        int bytes = Inline.validate(b.get("content"), true, true);
        cap(bytes, 8 * 1024);
    }

    private static void heading(JsonValue.Obj b) {
        Closed.check(b, Set.of("kind", "level", "content"), Set.of("kind", "level", "content"));
        Fields.integerInRange(b.get("level"), 1, 6);
        int bytes = Inline.validate(b.get("content"), true, true);
        cap(bytes, 200);
    }

    private static void codeBlock(JsonValue.Obj b) {
        Closed.check(b, Set.of("kind", "language", "content"), Set.of("kind", "language", "content"));
        slugLanguage(Fields.str(b.get("language")));
        String content = Fields.str(b.get("content"));
        if (Fields.utf8Len(content) > 32 * 1024) {
            throw new RejectException(DiagnosticCode.E_SCHEMA_FIELD_LENGTH);
        }
        // Control chars other than line feed are forbidden; NFC required (section 04).
        Fields.noControlChars(content, true);
        Fields.requireNfc(content);
    }

    private static void quote(JsonValue.Obj b) {
        Closed.check(b, Set.of("kind", "content", "attribution"), Set.of("kind", "content"));
        int bytes = Inline.validate(b.get("content"), true, true);
        cap(bytes, 4 * 1024);
        if (b.has("attribution")) {
            int abytes = Inline.validate(b.get("attribution"), true, true);
            cap(abytes, 200);
        }
    }

    private static void list(JsonValue.Obj b) {
        Closed.check(b, Set.of("kind", "ordered", "items"), Set.of("kind", "ordered", "items"));
        Fields.bool(b.get("ordered"));
        List<JsonValue> items = Fields.arr(b.get("items")).elements();
        if (items.isEmpty()) {
            throw new RejectException(DiagnosticCode.E_SCHEMA_REQUIRED_FIELD);
        }
        if (items.size() > 64) {
            throw new RejectException(DiagnosticCode.E_SCHEMA_FIELD_LENGTH);
        }
        int total = 0;
        for (JsonValue item : items) {
            total += Inline.validate(item, true, true);
        }
        cap(total, 8 * 1024);
    }

    private static void divider(JsonValue.Obj b) {
        Closed.check(b, Set.of("kind"), Set.of("kind"));
    }

    private static void image(JsonValue.Obj b) {
        Closed.check(b,
                Set.of("kind", "src", "sha256", "media_type", "width", "height", "alt", "caption"),
                Set.of("kind", "src", "sha256", "media_type", "width", "height", "alt"));
        Fields.path(Fields.str(b.get("src")));
        sha256Field(Fields.str(b.get("sha256")));
        Fields.inEnum(Fields.str(b.get("media_type")), MEDIA_TYPES);
        Fields.integerInRange(b.get("width"), 1, 4096);
        Fields.integerInRange(b.get("height"), 1, 4096);
        String alt = Fields.str(b.get("alt"));
        Fields.maxBytes(alt, 1024);
        Fields.noControlChars(alt, false);
        Fields.requireNfc(alt);
        if (b.has("caption")) {
            String caption = Fields.str(b.get("caption"));
            if (caption.isEmpty()) {
                // An empty caption must be omitted, not present as "".
                throw Fields.syntax();
            }
            Fields.maxBytes(caption, 500);
            Fields.noControlChars(caption, false);
            Fields.requireNfc(caption);
        }
    }

    private static void link(JsonValue.Obj b) {
        Closed.check(b, Set.of("kind", "label", "target"), Set.of("kind", "label", "target"));
        // link.label is inline content that MUST NOT contain link elements.
        int bytes = Inline.validate(b.get("label"), false, true);
        cap(bytes, 200);
        Inline.validateTarget(b.get("target"));
    }

    private static void submitForm(JsonValue.Obj b) {
        Closed.check(b, Set.of("kind", "label", "submit_to", "fields", "submit_label"),
                Set.of("kind", "label", "submit_to", "fields", "submit_label"));
        Inline.validate(b.get("label"), false, true);
        Fields.path(Fields.str(b.get("submit_to")));
        List<JsonValue> fields = Fields.arr(b.get("fields")).elements();
        if (fields.isEmpty()) {
            throw new RejectException(DiagnosticCode.E_SCHEMA_REQUIRED_FIELD);
        }
        if (fields.size() > 16) {
            throw new RejectException(DiagnosticCode.E_SCHEMA_FIELD_LENGTH);
        }
        Set<String> names = new HashSet<>();
        for (JsonValue f : fields) {
            String name = formField(Fields.obj(f));
            if (!names.add(name)) {
                throw new RejectException(DiagnosticCode.E_SCHEMA_DUPLICATE_ENTRY);
            }
        }
        String submitLabel = Fields.str(b.get("submit_label"));
        Fields.maxBytes(submitLabel, 100);
        Fields.noControlChars(submitLabel, false);
        // section 04:159: submit_form form-level labels are user-visible; NFC required.
        Fields.requireNfc(submitLabel);
    }

    private static String formField(JsonValue.Obj f) {
        String kind = Fields.str(Inline.require(f, "kind"));
        Fields.inEnum(kind, FIELD_KINDS);
        String name;
        switch (kind) {
            case "text", "textarea" -> {
                Closed.check(f, Set.of("kind", "name", "label", "required", "max_length"),
                        Set.of("kind", "name", "label", "required", "max_length"));
                name = sharedFormFields(f);
                Fields.integerInRange(f.get("max_length"), 1, 8192);
            }
            case "select" -> {
                Closed.check(f, Set.of("kind", "name", "label", "required", "options"),
                        Set.of("kind", "name", "label", "required", "options"));
                name = sharedFormFields(f);
                selectOptions(f.get("options"));
            }
            case "checkbox" -> {
                Closed.check(f, Set.of("kind", "name", "label", "required"),
                        Set.of("kind", "name", "label", "required"));
                name = sharedFormFields(f);
            }
            default -> throw new RejectException(DiagnosticCode.E_SCHEMA_ENUM_VIOLATION);
        }
        return name;
    }

    private static String sharedFormFields(JsonValue.Obj f) {
        String name = Fields.str(f.get("name"));
        Fields.slug(name, 64);
        String label = Fields.str(f.get("label"));
        Fields.maxBytes(label, 200);
        Fields.noControlChars(label, false);
        // section 04:159: submit_form field labels are user-visible; NFC required.
        Fields.requireNfc(label);
        Fields.bool(f.get("required"));
        return name;
    }

    private static void selectOptions(JsonValue optionsValue) {
        List<JsonValue> options = Fields.arr(optionsValue).elements();
        if (options.isEmpty()) {
            throw new RejectException(DiagnosticCode.E_SCHEMA_REQUIRED_FIELD);
        }
        if (options.size() > 32) {
            throw new RejectException(DiagnosticCode.E_SCHEMA_FIELD_LENGTH);
        }
        Set<String> values = new HashSet<>();
        for (JsonValue o : options) {
            JsonValue.Obj opt = Fields.obj(o);
            Closed.check(opt, Set.of("value", "label"), Set.of("value", "label"));
            String value = Fields.str(opt.get("value"));
            Fields.slug(value, 64);
            if (!values.add(value)) {
                throw new RejectException(DiagnosticCode.E_SCHEMA_DUPLICATE_ENTRY);
            }
            String label = Fields.str(opt.get("label"));
            Fields.maxBytes(label, 200);
            Fields.noControlChars(label, false);
            // section 04:159: submit_form option labels are user-visible; NFC required.
            Fields.requireNfc(label);
        }
    }

    private static void feedback(JsonValue.Obj b) {
        Closed.check(b, Set.of("kind", "variant", "content"), Set.of("kind", "variant", "content"));
        Fields.inEnum(Fields.str(b.get("variant")), FEEDBACK_VARIANTS);
        int bytes = Inline.validate(b.get("content"), true, true);
        cap(bytes, 2 * 1024);
    }

    private static void note(JsonValue.Obj b) {
        Closed.check(b, Set.of("kind", "variant", "title", "content"), Set.of("kind", "variant", "content"));
        Fields.inEnum(Fields.str(b.get("variant")), NOTE_VARIANTS);
        if (b.has("title")) {
            String title = Fields.str(b.get("title"));
            if (title.isEmpty()) {
                throw Fields.syntax();
            }
            Fields.maxBytes(title, 200);
            Fields.noControlChars(title, false);
            Fields.requireNfc(title);
        }
        int bytes = Inline.validate(b.get("content"), true, true);
        cap(bytes, 4 * 1024);
    }

    private static void slugLanguage(String language) {
        // code_block.language: [a-z0-9_-], begins [a-z0-9], non-empty, <= 64.
        Fields.slug(language, 64);
    }

    private static void sha256Field(String s) {
        // "sha-256:" + 43 base64url chars = 51 chars total.
        if (s.length() != 51 || !s.startsWith("sha-256:")) {
            throw Fields.syntax();
        }
        Fields.base64url(s.substring("sha-256:".length()), 32);
    }

    private static void cap(int bytes, int max) {
        if (bytes > max) {
            throw new RejectException(DiagnosticCode.E_SCHEMA_FIELD_LENGTH);
        }
    }
}
