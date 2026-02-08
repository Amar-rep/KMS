package com.example.kms.service;

import com.example.kms.exception.DecryptionException;
import com.example.kms.exception.EncryptionException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

@Slf4j
@Service
public class EncryptionService {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int KEY_SIZE = 128;
    private static final int IV_SIZE = 12; // 96 bits for GCM
    private static final int TAG_LENGTH_BITS = 128;
    private static final int TAG_LENGTH_BYTES = 16;

    /**
     * Result of encryption containing encrypted payload and key.
     * Payload format: [ IV (12 bytes) ][ CIPHERTEXT ][ TAG (16 bytes) ]
     */
    public record EncryptionResult(byte[] encryptedPayload, String keyBase64) {
    }

    /**
     * Encrypts the given data using AES-128-GCM.
     * Returns payload with embedded IV and auth tag.
     * Format: [ IV (12 bytes) ][ CIPHERTEXT + TAG ]
     * Note: GCM mode appends the auth tag to ciphertext automatically.
     */
    public EncryptionResult encrypt(byte[] data) {
        try {
            log.debug("Encrypting {} bytes of data", data.length);

            // Generate AES-128 key
            KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
            keyGen.init(KEY_SIZE);
            SecretKey secretKey = keyGen.generateKey();

            // Generate random IV
            byte[] iv = new byte[IV_SIZE];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);

            // Encrypt (GCM automatically appends auth tag to ciphertext)
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
            byte[] ciphertextWithTag = cipher.doFinal(data);

            // Build payload: IV + ciphertext + tag
            byte[] payload = new byte[IV_SIZE + ciphertextWithTag.length];
            System.arraycopy(iv, 0, payload, 0, IV_SIZE);
            System.arraycopy(ciphertextWithTag, 0, payload, IV_SIZE, ciphertextWithTag.length);

            // Encode key to Base64
            String keyBase64 = Base64.getEncoder().encodeToString(secretKey.getEncoded());

            log.info("Successfully encrypted data, payload size: {} bytes", payload.length);
            return new EncryptionResult(payload, keyBase64);
        } catch (Exception e) {
            log.error("Encryption failed", e);
            throw new EncryptionException("Failed to encrypt data: " + e.getMessage(), e);
        }
    }

    /**
     * Encrypts the given data using AES-GCM with a provided DEK (Data Encryption
     * Key).
     * This method uses the provided key instead of generating a new one.
     * Returns payload with embedded IV and auth tag.
     * Format: [ IV (12 bytes) ][ CIPHERTEXT + TAG ]
     * 
     * @param data The data to encrypt
     * @param dek  The Data Encryption Key to use for encryption
     * @return Encrypted payload (IV + ciphertext + tag)
     */
    public byte[] encryptWithDEK(byte[] data, SecretKey dek) {
        try {
            log.debug("Encrypting {} bytes of data with provided DEK", data.length);

            // Generate random IV
            byte[] iv = new byte[IV_SIZE];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);

            // Encrypt (GCM automatically appends auth tag to ciphertext)
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, dek, gcmSpec);
            byte[] ciphertextWithTag = cipher.doFinal(data);

            // Build payload: IV + ciphertext + tag
            byte[] payload = new byte[IV_SIZE + ciphertextWithTag.length];
            System.arraycopy(iv, 0, payload, 0, IV_SIZE);
            System.arraycopy(ciphertextWithTag, 0, payload, IV_SIZE, ciphertextWithTag.length);

            log.info("Successfully encrypted data with DEK, payload size: {} bytes", payload.length);
            return payload;
        } catch (Exception e) {
            log.error("Encryption with DEK failed", e);
            throw new EncryptionException("Failed to encrypt data with DEK: " + e.getMessage(), e);
        }
    }

    /**
     * Decrypts the given payload using AES-128-GCM.
     * Extracts IV and auth tag from the payload.
     * Payload format: [ IV (12 bytes) ][ CIPHERTEXT ][ TAG (16 bytes) ]
     */
    public byte[] decrypt(byte[] payload, String keyBase64) {
        try {
            log.debug("Decrypting {} bytes of payload", payload.length);

            // Decode key from Base64
            byte[] keyBytes = Base64.getDecoder().decode(keyBase64);
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, ALGORITHM);

            // Extract IV (first 12 bytes)
            byte[] iv = Arrays.copyOfRange(payload, 0, IV_SIZE);

            // Extract ciphertext + tag (remaining bytes)
            byte[] ciphertextWithTag = Arrays.copyOfRange(payload, IV_SIZE, payload.length);

            // Decrypt
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);

            byte[] decryptedData = cipher.doFinal(ciphertextWithTag);
            log.info("Successfully decrypted data, size: {} bytes", decryptedData.length);
            return decryptedData;
        } catch (Exception e) {
            log.error("Decryption failed", e);
            throw new DecryptionException("Failed to decrypt data: " + e.getMessage(), e);
        }
    }

    /**
     * Decrypts the given payload using AES-GCM with a provided DEK (Data Encryption
     * Key).
     * This method uses the provided key directly instead of a Base64 string.
     * Extracts IV and auth tag from the payload.
     * Payload format: [ IV (12 bytes) ][ CIPHERTEXT ][ TAG (16 bytes) ]
     * 
     * @param payload The encrypted payload (IV + ciphertext + tag)
     * @param dek     The Data Encryption Key to use for decryption
     * @return Decrypted data
     */
    public byte[] decryptWithDEK(byte[] payload, SecretKey dek) {
        try {
            log.debug("Decrypting {} bytes of payload with provided DEK", payload.length);

            // Extract IV (first 12 bytes)
            byte[] iv = Arrays.copyOfRange(payload, 0, IV_SIZE);

            // Extract ciphertext + tag (remaining bytes)
            byte[] ciphertextWithTag = Arrays.copyOfRange(payload, IV_SIZE, payload.length);

            // Decrypt
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, dek, gcmSpec);

            byte[] decryptedData = cipher.doFinal(ciphertextWithTag);
            log.info("Successfully decrypted data with DEK, size: {} bytes", decryptedData.length);
            return decryptedData;
        } catch (Exception e) {
            log.error("Decryption with DEK failed", e);
            throw new DecryptionException("Failed to decrypt data with DEK: " + e.getMessage(), e);
        }
    }
}
