package org.entangled;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Test helper: read raw corpus bytes from the checked-in copy under
 * {@code src/test/resources/corpus}. Bytes are read with no normalization and
 * no transcoding, as the corpus harness contract requires (corpus/README.md).
 */
final class CorpusFiles {

    static final Path ROOT = Paths.get("src", "test", "resources", "corpus");

    private CorpusFiles() {
    }

    static byte[] bytes(String relative) {
        try {
            return Files.readAllBytes(ROOT.resolve(relative));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    static byte[] vectorInput(String vectorId) {
        return bytes("vectors/" + vectorId + "/input.json");
    }

    static byte[] classpath(String resource) {
        try (InputStream in = CorpusFiles.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IllegalArgumentException("missing resource: " + resource);
            }
            return in.readAllBytes();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
