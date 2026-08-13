package net.tcpshield.tcpshield.util.validation;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.stream.Stream;

/**
 * A signature validator using the TCPShield public key
 */
public class SignatureValidator {
    private final List<PublicKey> publicKeys;

    public SignatureValidator() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, URISyntaxException {
        URI uri = Objects.requireNonNull(getClass().getResource("/keys")).toURI();

        List<PublicKey> keys = new ArrayList<>();

        try (FileSystem fileSystem = FileSystems.newFileSystem(uri, Collections.emptyMap())) {
            Path path = fileSystem.getPath("/keys");
            try (Stream<Path> walk = Files.walk(path, 1)) {
                List<Path> paths = walk.toList();
                for (Path p : paths) {
                    if (p.equals(path) || !Files.isRegularFile(p)) continue;

                    byte[] encodedKey = Files.readAllBytes(p);
                    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);

                    KeyFactory keyFactory = KeyFactory.getInstance("EC");
                    keys.add(keyFactory.generatePublic(keySpec));
                }
            }
        }

        publicKeys = keys;
    }

    /**
     * Validates a String and Signature pair
     *
     * @param str       The data in the form of a string
     * @param signature The provided signature
     * @return Boolean stating if it's a valid signature
     */
    public boolean validate(String str, String signature) {
        return validate(str.getBytes(StandardCharsets.UTF_8), signature);
    }

    /**
     * Validates a byte[] and Signature pair
     *
     * @param data      The data in the form of a byte array
     * @param signature The provided signature
     * @return Boolean stating if it's a valid signature
     */
    private boolean validate(byte[] data, String signature) {
        try {
            byte[] decodedSignature = Base64.getDecoder().decode(signature);

            for (PublicKey key : publicKeys) {
                Signature sig = Signature.getInstance("SHA512withECDSA");
                sig.initVerify(key);
                sig.update(data);
                if (sig.verify(decodedSignature)) return true;
            }
        } catch (IllegalArgumentException | SignatureException | NoSuchAlgorithmException | InvalidKeyException e) {
            return false;
        }

        return false;
    }
}
