package com.example.kms.service;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.springframework.stereotype.Service;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;
import com.example.kms.entity.AppUser;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;
import java.util.Arrays;
import org.web3j.crypto.Hash;

/**
 * KeyService provides cryptographic operations for key management in the KMS
 * system.
 * 
 * <p>
 * Security Design Decisions:
 * <ul>
 * <li>ECIES: Uses Elliptic Curve Integrated Encryption Scheme with BouncyCastle
 * provider for asymmetric encryption, compatible with Web3j secp256k1
 * keys.</li>
 * <li>AES-GCM: Uses AES/GCM/NoPadding for symmetric encryption. GCM provides
 * both confidentiality and authenticity with a 128-bit authentication tag.</li>
 * <li>Key Sizes: 128-bit for DEK (data encryption), 256-bit for Group Keys
 * (KEK).</li>
 * <li>IV/Nonce: Uses 12-byte (96-bit) nonces for GCM as recommended by
 * NIST.</li>
 * <li>SecureRandom: All random values use cryptographically secure random
 * generation.</li>
 * </ul>
 * 
 * @author Senior Java Security Engineer
 * @version 1.1
 */
@Service
public class KeyService {

    private static final String AES_ALGORITHM = "AES";
    private static final String ECIES_ALGORITHM = "ECIES";
    private static final String BOUNCY_CASTLE_PROVIDER = "BC";
    private static final String EC_ALGORITHM = "EC";
    private static final String SECP256K1_CURVE = "secp256k1";
    private static final String AES_GCM_ALGORITHM = "AES/GCM/NoPadding";

    private static final int DEK_KEY_SIZE = 128; // bits
    private static final int GROUP_KEY_SIZE = 256; // bits
    private static final int GCM_IV_LENGTH = 12; // bytes (96 bits - recommended for GCM)
    private static final int GCM_TAG_LENGTH = 128; // bits (authentication tag)

    private static final String BASE62_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private static final int GROUP_ID_LENGTH = 10;
    private static final int RECORD_ID_LENGTH = 12;

    private final SecureRandom secureRandom;
    private final com.example.kms.service.UserService userService;

    public KeyService(com.example.kms.service.UserService userService) {
        // Register BouncyCastle as a security provider for ECIES support
        Security.addProvider(new BouncyCastleProvider());
        this.secureRandom = new SecureRandom();
        this.userService = userService;
    }

    /**
     * Generates a 128-bit AES Data Encryption Key (DEK).
     * 
     * <p>
     * The DEK is used to encrypt actual data/documents. Using 128-bit AES provides
     * sufficient security for most use cases while maintaining good performance.
     * 
     * @return A cryptographically secure 128-bit AES SecretKey
     * @throws RuntimeException if key generation fails
     */
    public SecretKey generateDEK() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(AES_ALGORITHM);
            keyGenerator.init(DEK_KEY_SIZE, secureRandom);
            return keyGenerator.generateKey();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Failed to generate DEK", e);
        }
    }

    /**
     * Generates a 256-bit AES Group Key (Key Encryption Key).
     * 
     * <p>
     * The Group Key is used to encrypt DEKs, forming a key hierarchy. Using 256-bit
     * AES provides the highest standard security level for key encryption keys.
     * 
     * @return A cryptographically secure 256-bit AES SecretKey
     * @throws RuntimeException if key generation fails
     */
    public SecretKey generateGroupKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(AES_ALGORITHM);
            keyGenerator.init(GROUP_KEY_SIZE, secureRandom);
            return keyGenerator.generateKey();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Failed to generate Group Key", e);
        }
    }

    /**
     * Encrypts a symmetric key (DEK or Group Key) using ECIES (Elliptic Curve
     * Integrated Encryption Scheme).
     * 
     * <p>
     * Uses ECIES with BouncyCastle provider which provides:
     * <ul>
     * <li>Compatibility with Web3j secp256k1 elliptic curve keys</li>
     * <li>Semantic security (same plaintext produces different ciphertexts)</li>
     * <li>Integrated encryption combining ECDH key agreement with symmetric
     * encryption</li>
     * </ul>
     * 
     * <p>
     * The recipient can decrypt this using their corresponding EC private key.
     * 
     * @param keyToEncrypt The symmetric key (DEK or GroupKey) to encrypt
     * @param publicKey    The EC public key (secp256k1) used for encryption
     * @return Base64-encoded encrypted key
     * @throws RuntimeException if encryption fails
     */
    public String encryptKeyWithPublicKey(SecretKey keyToEncrypt, PublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance(ECIES_ALGORITHM, BOUNCY_CASTLE_PROVIDER);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            byte[] encryptedKey = cipher.doFinal(keyToEncrypt.getEncoded());
            return Base64.getEncoder().encodeToString(encryptedKey);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Failed to encrypt key with EC public key", e);
        }
    }

    /**
     * Converts raw EC public key bytes (from Web3j or similar) to a Java PublicKey.
     * 
     * <p>
     * Web3j typically provides public keys as a BigInteger or raw byte array.
     * This method converts those raw bytes into a proper Java PublicKey object
     * that can be used with the ECIES cipher.
     * 
     * <p>
     * The input should be the uncompressed public key point (65 bytes with 0x04
     * prefix,
     * or 64 bytes without prefix representing X and Y coordinates).
     * 
     * @param publicKeyBytes The raw public key bytes (64 or 65 bytes)
     * @return A Java PublicKey suitable for ECIES encryption
     * @throws RuntimeException if conversion fails
     */
    public PublicKey convertToECPublicKey(byte[] publicKeyBytes) {
        try {
            ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(SECP256K1_CURVE);

            // Handle both formats: with 0x04 prefix (65 bytes) or without (64 bytes)
            byte[] keyBytes = publicKeyBytes;
            if (publicKeyBytes.length == 64) {
                // Add the uncompressed point prefix
                keyBytes = new byte[65];
                keyBytes[0] = 0x04;
                System.arraycopy(publicKeyBytes, 0, keyBytes, 1, 64);
            }

            ECPoint ecPoint = ecSpec.getCurve().decodePoint(keyBytes);
            ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(ecPoint, ecSpec);

            KeyFactory keyFactory = KeyFactory.getInstance(EC_ALGORITHM, BOUNCY_CASTLE_PROVIDER);
            return keyFactory.generatePublic(pubKeySpec);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Failed to convert bytes to EC PublicKey", e);
        }
    }

    /**
     * Converts a BigInteger public key (from Web3j) to a Java PublicKey.
     * 
     * <p>
     * Web3j's ECKeyPair.getPublicKey() returns a BigInteger representing
     * the public key point. This method converts it to a proper Java PublicKey.
     * 
     * @param publicKeyBigInt The public key as BigInteger from Web3j
     * @return A Java PublicKey suitable for ECIES encryption
     * @throws RuntimeException if conversion fails
     */
    public PublicKey convertToECPublicKey(BigInteger publicKeyBigInt) {
        // Convert BigInteger to 64-byte array (32 bytes for X, 32 bytes for Y)
        byte[] publicKeyBytes = publicKeyBigInt.toByteArray();

        // BigInteger may add a leading zero byte for sign, or may be shorter than 64
        // bytes
        byte[] adjustedBytes = new byte[64];
        if (publicKeyBytes.length >= 64) {
            // Take the last 64 bytes (handles leading zero byte case)
            System.arraycopy(publicKeyBytes, publicKeyBytes.length - 64, adjustedBytes, 0, 64);
        } else {
            // Pad with leading zeros if shorter
            System.arraycopy(publicKeyBytes, 0, adjustedBytes, 64 - publicKeyBytes.length, publicKeyBytes.length);
        }

        return convertToECPublicKey(adjustedBytes);
    }

    /**
     * Encrypts a DEK using a Group Key with AES-GCM.
     * 
     * <p>
     * AES-GCM (Galois/Counter Mode) provides:
     * <ul>
     * <li>Authenticated encryption (confidentiality + integrity)</li>
     * <li>High performance (parallelizable)</li>
     * <li>128-bit authentication tag to detect tampering</li>
     * </ul>
     * 
     * <p>
     * The output format is: [12-byte IV][Ciphertext + Auth Tag]
     * The IV is prepended to allow for easy extraction during decryption.
     * 
     * <p>
     * <strong>CRITICAL:</strong> Each encryption MUST use a unique IV. This
     * implementation
     * generates a fresh random IV for every call using SecureRandom.
     * 
     * @param dek      The Data Encryption Key to encrypt
     * @param groupKey The Group Key used for encryption
     * @return Base64-encoded string containing IV + Ciphertext
     * @throws RuntimeException if encryption fails
     */
    public String encryptDEKWithGroupKey(SecretKey dek, SecretKey groupKey) {
        try {
            // Generate a unique 12-byte IV for this encryption operation
            byte[] iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(iv);

            // Initialize cipher with GCM parameters
            Cipher cipher = Cipher.getInstance(AES_GCM_ALGORITHM);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, groupKey, gcmSpec);

            // Encrypt the DEK
            byte[] encryptedDEK = cipher.doFinal(dek.getEncoded());

            // Combine IV + Ciphertext for storage/transmission
            ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + encryptedDEK.length);
            byteBuffer.put(iv);
            byteBuffer.put(encryptedDEK);

            return Base64.getEncoder().encodeToString(byteBuffer.array());
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Failed to encrypt DEK with Group Key", e);
        }
    }

    /**
     * Decrypts an encrypted DEK using the Group Key with AES-GCM.
     *
     * <p>
     * Reverses the process of
     * {@link #encryptDEKWithGroupKey(SecretKey, SecretKey)}.
     * Expects input format: [12-byte IV][Ciphertext + Auth Tag]
     *
     * @param encDekGroupBase64 Base64-encoded string containing IV + Encrypted DEK
     * @param groupKeyBase64    Base64-encoded Group Key
     * @return The decrypted Data Encryption Key (DEK)
     * @throws RuntimeException if decryption fails
     */
    public SecretKey decryptDEKWithGroupKey(String encDekGroupBase64, String groupKeyBase64) {
        try {
            // Restore Group Key
            SecretKey groupKey = base64ToSecretKey(groupKeyBase64, AES_ALGORITHM);

            // Decode the encrypted blob
            byte[] docBytes = Base64.getDecoder().decode(encDekGroupBase64);

            // Extract IV
            ByteBuffer byteBuffer = ByteBuffer.wrap(docBytes);
            byte[] iv = new byte[GCM_IV_LENGTH];
            byteBuffer.get(iv);

            // Extract Ciphertext
            byte[] ciphertext = new byte[byteBuffer.remaining()];
            byteBuffer.get(ciphertext);

            // Initialize Cipher for Decryption
            Cipher cipher = Cipher.getInstance(AES_GCM_ALGORITHM);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, groupKey, gcmSpec);

            // Decrypt
            byte[] dekBytes = cipher.doFinal(ciphertext);

            // Reconstruct DEK
            return new SecretKeySpec(dekBytes, AES_ALGORITHM);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Failed to decrypt DEK with Group Key", e);
        }
    }

    /**
     * Generates a cryptographically secure, URL-safe 10-character Group ID.
     * 
     * <p>
     * Uses Base62 encoding (A-Za-z0-9) which is URL-safe and human-readable.
     * With 10 characters from a 62-character alphabet, this provides 62^10
     * (approximately 8.4 × 10^17) possible combinations, making collisions
     * extremely unlikely.
     * 
     * @return A 10-character unique group identifier
     */
    public String generateGroupID() {
        return generateRandomString(GROUP_ID_LENGTH);
    }

    /**
     * Generates a cryptographically secure, URL-safe 12-character Record ID.
     * 
     * <p>
     * Uses Base62 encoding (A-Za-z0-9) which is URL-safe and human-readable.
     * With 12 characters from a 62-character alphabet, this provides 62^12
     * (approximately 3.2 × 10^21) possible combinations, ensuring very high
     * uniqueness.
     * 
     * @return A 12-character unique record identifier
     */
    public String generateRecordID() {
        return generateRandomString(RECORD_ID_LENGTH);
    }

    /**
     * Converts a Base64-encoded string back to a SecretKey.
     * 
     * <p>
     * This is useful for testing and for reconstructing keys from storage.
     * The algorithm parameter should match the original key type (typically "AES").
     * 
     * @param base64Key Base64-encoded key bytes
     * @param algorithm The algorithm name (e.g., "AES")
     * @return The reconstructed SecretKey
     */
    public SecretKey base64ToSecretKey(String base64Key, String algorithm) {
        byte[] decodedKey = Base64.getDecoder().decode(base64Key);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, algorithm);
    }

    /**
     * Converts a SecretKey (AES DEK or Group Key) into a Base64 string.
     *
     * @param secretKey The key object to encode
     * @return A Base64 encoded string of the raw key bytes
     */
    public String secretKeyToBase64(SecretKey secretKey) {
        if (secretKey == null) {
            throw new IllegalArgumentException("Key cannot be null");
        }
        // .getEncoded() returns the raw byte[] of the AES key
        byte[] rawKeyBytes = secretKey.getEncoded();

        // Encode those bytes to a Base64 string
        return Base64.getEncoder().encodeToString(rawKeyBytes);
    }

    /**
     * Generates a cryptographically secure random string using Base62 alphabet.
     * 
     * <p>
     * This helper method is used by both generateGroupID() and generateRecordID().
     * It uses SecureRandom to ensure unpredictability and collision resistance.
     * 
     * <p>
     * Each character is independently and uniformly selected from the 62-character
     * alphabet, providing strong entropy for identifier generation.
     * 
     * @param length The desired length of the random string
     * @return A random string of the specified length using Base62 characters
     */
    private String generateRandomString(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            int randomIndex = secureRandom.nextInt(BASE62_ALPHABET.length());
            sb.append(BASE62_ALPHABET.charAt(randomIndex));
        }
        return sb.toString();
    }

    /**
     * Verifies an ECDSA signature for a given nonce using the user's public key.
     * 
     * <p>
     * This method:
     * <ul>
     * <li>Fetches the user from the database using their Keccak ID</li>
     * <li>Recovers the public key from the signature</li>
     * <li>Verifies that the recovered public key matches the user's stored public
     * key</li>
     * </ul>
     * 
     * <p>
     * The signature should be in the format produced by Web3j/Ethereum wallets:
     * 65 bytes containing r (32 bytes), s (32 bytes), and v (1 byte), encoded in
     * Base64.
     * 
     * @param nonce           The original nonce string that was signed
     * @param signatureBase64 The signature in Base64 format
     * @param userIdKeccak    The Keccak256 hash of the user's Ethereum address
     * @return true if the signature is valid and matches the user's public key
     * @throws RuntimeException if the user is not found or signature verification
     *                          fails
     */
    public boolean verifySignature(String nonce, String signatureBase64, String userIdKeccak) {
        try {
            // Fetch the user from the database
            AppUser user = userService.findByKeccak(userIdKeccak);
            if (user == null) {
                throw new RuntimeException("User not found with Keccak ID: " + userIdKeccak);
            }

            // Get the stored public key
            byte[] storedPublicKey = user.getPublicKey();

            // Decode Base64 signature to bytes
            byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);

            if (signatureBytes.length != 65) {
                throw new IllegalArgumentException(
                        "Invalid signature length. Expected 65 bytes, got " + signatureBytes.length);
            }

            // Extract r, s, v from signature
            byte[] r = Arrays.copyOfRange(signatureBytes, 0, 32);
            byte[] s = Arrays.copyOfRange(signatureBytes, 32, 64);
            byte v = signatureBytes[64];

            // Normalize v (should be 27 or 28 for Ethereum, or 0 or 1)
            if (v < 27) {
                v = (byte) (v + 27);
            }

            // Create Sign.SignatureData
            Sign.SignatureData signatureData = new Sign.SignatureData(v, r, s);

            // Hash the nonce (Ethereum uses Keccak256 of the message)
            byte[] messageHash = Hash.sha3(nonce.getBytes(StandardCharsets.UTF_8));

            // Recover public key from signature
            BigInteger recoveredPublicKey = Sign.signedMessageHashToKey(messageHash, signatureData);

            // Convert recovered public key to bytes (64 bytes without 0x04 prefix)
            byte[] recoveredPublicKeyBytes = Numeric.toBytesPadded(recoveredPublicKey, 64);

            // Compare with stored public key
            // Note: storedPublicKey might be 64 or 65 bytes (with or without 0x04 prefix)
            byte[] storedKeyToCompare = storedPublicKey;
            if (storedPublicKey.length == 65 && storedPublicKey[0] == 0x04) {
                // Remove the 0x04 prefix for comparison
                storedKeyToCompare = Arrays.copyOfRange(storedPublicKey, 1, 65);
            }

            return Arrays.equals(recoveredPublicKeyBytes, storedKeyToCompare);

        } catch (Exception e) {
            throw new RuntimeException("Failed to verify signature: " + e.getMessage(), e);
        }
    }
}
