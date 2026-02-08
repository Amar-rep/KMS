package com.example.kms.exception;

/**
 * Exception thrown when encryption operations fail.
 */
public class EncryptionException extends KmsException {

    public EncryptionException(String developerMessage, Throwable cause) {
        super(
                "Failed to encrypt document. Please try again.",
                developerMessage,
                "ENCRYPTION_ERROR",
                cause);
    }
}
