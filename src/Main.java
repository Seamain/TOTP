import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;

class Base32 {
    private static final int[] base32Lookup = {0xFF, 0xFF, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, // '0', '1', '2', '3', '4', '5', '6', '7'
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // '8', '9', ':',
            // ';', '<', '=',
            // '>', '?'
            0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // '@', 'A', 'B',
            // 'C', 'D', 'E',
            // 'F', 'G'
            0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, // 'H', 'I', 'J',
            // 'K', 'L', 'M',
            // 'N', 'O'
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, // 'P', 'Q', 'R',
            // 'S', 'T', 'U',
            // 'V', 'W'
            0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 'X', 'Y', 'Z',
            // '[', '', ']',
            // '^', '_'
            0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // '`', 'a', 'b',
            // 'c', 'd', 'e',
            // 'f', 'g'
            0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, // 'h', 'i', 'j',
            // 'k', 'l', 'm',
            // 'n', 'o'
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, // 'p', 'q', 'r',
            // 's', 't', 'u',
            // 'v', 'w'
            0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF // 'x', 'y', 'z',
            // '{', '|', '}',
            // '~', 'DEL'
    };

    /**
     * Decodes the given Base32 String to a raw byte array.
     *
     * @return Decoded <code>base32</code> String as a raw byte array.
     */
    static public byte[] decode(final String base32) {
        int i, index, lookup, offset, digit;
        byte[] bytes = new byte[base32.length() * 5 / 8];
        for (i = 0, index = 0, offset = 0; i < base32.length(); i++) {
            lookup = base32.charAt(i) - '0';
            /* Skip chars outside the lookup table */
            if (lookup < 0 || lookup >= base32Lookup.length) {
                continue;
            }
            digit = base32Lookup[lookup];
            /* If this digit is not in the table, ignore it */
            if (digit == 0xFF) {
                continue;
            }
            if (index <= 3) {
                index = (index + 5) % 8;
                if (index == 0) {
                    bytes[offset] |= digit;
                    offset++;
                    if (offset >= bytes.length)
                        break;
                } else {
                    bytes[offset] |= digit << (8 - index);
                }
            } else {
                index = (index + 5) % 8;
                bytes[offset] |= (digit >>> index);
                offset++;
                if (offset >= bytes.length) {
                    break;
                }
                bytes[offset] |= digit << (8 - index);
            }
        }
        return bytes;
    }
}

class HOTP {
    private final byte[] Secret;
    private final byte[] Counter;
    private final int Digital;

    public HOTP(byte[] secret, long counter, int digital) {
        Secret = secret;
        Digital = digital;
        byte[] bytes = new byte[8];

        for (int i = 7; i >= 0; --i) {
            bytes[i] = (byte) (counter & 0xFF);

            counter >>= 8;
        }

        Counter = bytes;
    }

    private byte[] hmacSha1Encode(byte[] secret, byte[] counter) throws
            NoSuchAlgorithmException, InvalidKeyException {

        SecretKeySpec secretKeySpec = new SecretKeySpec(secret, "HmacSHA1"); // Useless GetBytes
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(secretKeySpec);

        return mac.doFinal(counter);
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    private String hexStringToRawString(String hexString) {
        StringBuilder rawString = new StringBuilder();
        for (int i = 0; i < hexString.length(); i += 2) {
            String hexPair = hexString.substring(i, i + 2);
            char c = (char) Integer.parseInt(hexPair, 16);
            rawString.append(c);
        }
        return rawString.toString();
    }

    public String getCode() throws NoSuchAlgorithmException, InvalidKeyException {
        var hs = hmacSha1Encode(Secret, Counter);
        var hsHex = bytesToHex(hs);
        var hsRawString = hexStringToRawString(hsHex);

        var offset = hsRawString.charAt(hsRawString.length() - 1) & 0xF;
        var code = ((hsRawString.charAt(offset) & 0x7F) << 24) |
                ((hsRawString.charAt(offset + 1) & 0xFF) << 16) |
                ((hsRawString.charAt(offset + 2) & 0xFF)) << 8 |
                (hsRawString.charAt(offset + 3) & 0xFF);
        var hotp = (int) (code % Math.pow(10, Digital));

        return String.format("%0" + Digital + "d", hotp);
    }
}

public class Main {
    public static String totp(String secret) throws NoSuchAlgorithmException, InvalidKeyException {
        /*
        o  X represents the time step in seconds (default value X =
          30 seconds) and is a system parameter.

       o  T0 is the Unix time to start counting time steps (default value is
          0, i.e., the Unix epoch) and is also a system parameter.

          More specifically, T = (Current Unix time - T0) / X, where the
           default floor function is used in the computation.

           Basically, we define TOTP as TOTP = HOTP(K, T)
         */

        var t = Instant.now().getEpochSecond() / 30;

        HOTP hotp = new HOTP(Base32.decode(secret), t, 6);

        return hotp.getCode();
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException {
        System.out.println(totp("I65VU7K5ZQL7WB4E"));
    }
}