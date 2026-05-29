package org.entangled.crypto;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Strict Ed25519 verification, RFC 8032 plus the additional rejections required
 * by section 05 ("Ed25519 verification profile").
 *
 * <p>A signature is accepted only if:
 * <ul>
 *   <li>the public key {@code A} is a canonical 32-byte compressed point on the
 *       curve and is not a small-order point (order dividing the cofactor 8);</li>
 *   <li>the signature is exactly 64 bytes, parsed as {@code R || S};</li>
 *   <li>{@code R} is a canonical compressed point on the curve and is not a
 *       small-order point;</li>
 *   <li>{@code S}, little-endian, satisfies {@code 0 <= S < L};</li>
 *   <li>the cofactorless equation {@code [S]B = R + [k]A} holds, where
 *       {@code k = SHA-512(R || A || M) mod L}.</li>
 * </ul>
 *
 * <p>This is the {@code verify_strict} profile section 05 names: small-order
 * rejection applies symmetrically to {@code A} and {@code R}, non-canonical
 * encodings of {@code A}/{@code R} are rejected, non-canonical {@code S}
 * ({@code S >= L}) is rejected, and verification is cofactorless (never the
 * cofactored {@code [8S]B = [8]R + [8][k]A} form). Pure-Java arithmetic with
 * {@link BigInteger} is used for unambiguous, dependency-free byte-level control;
 * the corpus is small so performance is not a concern.
 */
public final class Ed25519 {

    // Static initializers run in textual order, so each constant is declared
    // after the constants its initializer depends on.
    private static final BigInteger TWO = BigInteger.TWO;
    private static final BigInteger P =
            TWO.pow(255).subtract(BigInteger.valueOf(19));
    // Group order L = 2^252 + 27742317777372353535851937790883648493.
    private static final BigInteger L =
            TWO.pow(252).add(new BigInteger("27742317777372353535851937790883648493"));
    private static final BigInteger D =
            BigInteger.valueOf(-121665).multiply(inverse(BigInteger.valueOf(121666))).mod(P);

    // sqrt(-1) mod p, used in point decompression.
    private static final BigInteger I = TWO.modPow(P.subtract(BigInteger.ONE).divide(BigInteger.valueOf(4)), P);

    // Base point B (depends on D and I, so declared after them).
    private static final Point B = basePoint();

    private Ed25519() {
    }

    /**
     * Verify a signature under the strict profile.
     *
     * @param publicKey 32-byte compressed public key A
     * @param signature 64-byte signature R || S
     * @param message   the signature input M (context || 0x00 || JCS(payload))
     * @return true iff the signature is valid under the strict profile
     */
    public static boolean verify(byte[] publicKey, byte[] signature, byte[] message) {
        if (publicKey.length != 32 || signature.length != 64) {
            return false;
        }
        // Decode A; reject non-canonical encoding and small-order points.
        Point a = decodePoint(publicKey);
        if (a == null || isSmallOrder(a)) {
            return false;
        }
        byte[] rBytes = Arrays.copyOfRange(signature, 0, 32);
        byte[] sBytes = Arrays.copyOfRange(signature, 32, 64);

        // Decode R; reject non-canonical encoding and small-order points.
        Point r = decodePoint(rBytes);
        if (r == null || isSmallOrder(r)) {
            return false;
        }
        // S must be canonical: 0 <= S < L.
        BigInteger s = leToBigInteger(sBytes);
        if (s.compareTo(L) >= 0) {
            return false;
        }
        // k = SHA-512(R || A || M) mod L.
        byte[] kInput = concat(rBytes, publicKey, message);
        BigInteger k = leToBigInteger(Sha.sha512(kInput)).mod(L);

        // Cofactorless check: [S]B == R + [k]A.
        Point left = scalarMul(B, s);
        Point right = edwardsAdd(r, scalarMul(a, k));
        return pointEquals(left, right);
    }

    // --- Point model (affine, BigInteger coordinates mod p) ---

    private record Point(BigInteger x, BigInteger y) {
    }

    private static Point basePoint() {
        BigInteger by = BigInteger.valueOf(4).multiply(inverse(BigInteger.valueOf(5))).mod(P);
        BigInteger bx = recoverX(by, false);
        return new Point(bx, by);
    }

    private static boolean pointEquals(Point a, Point b) {
        return a.x.equals(b.x) && a.y.equals(b.y);
    }

    private static Point edwardsAdd(Point p1, Point p2) {
        BigInteger x1 = p1.x;
        BigInteger y1 = p1.y;
        BigInteger x2 = p2.x;
        BigInteger y2 = p2.y;
        BigInteger dxy = D.multiply(x1).multiply(x2).multiply(y1).multiply(y2).mod(P);
        BigInteger xNum = x1.multiply(y2).add(x2.multiply(y1)).mod(P);
        BigInteger xDen = BigInteger.ONE.add(dxy).mod(P);
        BigInteger yNum = y1.multiply(y2).add(x1.multiply(x2)).mod(P);
        BigInteger yDen = BigInteger.ONE.subtract(dxy).mod(P);
        BigInteger x3 = xNum.multiply(inverse(xDen)).mod(P);
        BigInteger y3 = yNum.multiply(inverse(yDen)).mod(P);
        return new Point(x3, y3);
    }

    private static Point scalarMul(Point point, BigInteger e) {
        Point result = new Point(BigInteger.ZERO, BigInteger.ONE); // neutral element
        Point base = point;
        BigInteger k = e;
        while (k.signum() > 0) {
            if (k.testBit(0)) {
                result = edwardsAdd(result, base);
            }
            base = edwardsAdd(base, base);
            k = k.shiftRight(1);
        }
        return result;
    }

    /**
     * A point is small-order if multiplying it by the cofactor 8 yields the
     * neutral element. RFC 8032 strict verification rejects such points for both
     * A and R (section 05).
     */
    private static boolean isSmallOrder(Point p) {
        Point eightP = scalarMul(p, BigInteger.valueOf(8));
        return eightP.x.signum() == 0 && eightP.y.equals(BigInteger.ONE);
    }

    /**
     * Decode a 32-byte compressed point. Returns null if the encoding is
     * non-canonical or does not decode to a curve point. The sign bit is the top
     * bit of the last byte; the remaining 255 bits are y, which must be < p
     * (canonical encoding).
     */
    private static Point decodePoint(byte[] enc) {
        BigInteger y = leToBigInteger(enc);
        BigInteger signBit = y.shiftRight(255).and(BigInteger.ONE);
        y = y.and(TWO.pow(255).subtract(BigInteger.ONE));
        // Canonical encoding requires y < p.
        if (y.compareTo(P) >= 0) {
            return null;
        }
        BigInteger x = recoverX(y, signBit.testBit(0));
        if (x == null) {
            return null;
        }
        return new Point(x, y);
    }

    /** Recover x from y and the sign bit on the Edwards curve, or null if none exists. */
    private static BigInteger recoverX(BigInteger y, boolean xIsOdd) {
        BigInteger y2 = y.multiply(y).mod(P);
        BigInteger num = y2.subtract(BigInteger.ONE).mod(P);
        BigInteger den = D.multiply(y2).add(BigInteger.ONE).mod(P);
        BigInteger xx = num.multiply(inverse(den)).mod(P);
        BigInteger x = xx.modPow(P.add(BigInteger.valueOf(3)).divide(BigInteger.valueOf(8)), P);
        if (!x.multiply(x).subtract(xx).mod(P).equals(BigInteger.ZERO)) {
            x = x.multiply(I).mod(P);
        }
        if (!x.multiply(x).subtract(xx).mod(P).equals(BigInteger.ZERO)) {
            return null; // no square root: not a valid point
        }
        if (x.testBit(0) != xIsOdd) {
            x = P.subtract(x);
        }
        return x;
    }

    private static BigInteger inverse(BigInteger a) {
        return a.modPow(P.subtract(TWO), P);
    }

    private static BigInteger leToBigInteger(byte[] le) {
        byte[] be = new byte[le.length];
        for (int i = 0; i < le.length; i++) {
            be[i] = le[le.length - 1 - i];
        }
        return new BigInteger(1, be);
    }

    private static byte[] concat(byte[] a, byte[] b, byte[] c) {
        byte[] out = new byte[a.length + b.length + c.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        System.arraycopy(c, 0, out, a.length + b.length, c.length);
        return out;
    }
}
