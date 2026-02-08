package com.example.kms.exception;

/**
 * Exception thrown when decryption operations fail.
 */
public class DecryptionException extends KmsException {

    public DecryptionException(String developerMessage, Throwable cause) {
        super(
                "Failed to decrypt document. The encryption key may be invalid or the document is corrupted.",
                developerMessage,
                "DECRYPTION_ERROR",
                cause);
    }
}
