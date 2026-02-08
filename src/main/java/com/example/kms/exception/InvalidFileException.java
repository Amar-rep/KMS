package com.example.kms.exception;

/**
 * Exception thrown when uploaded file is invalid.
 */
public class InvalidFileException extends KmsException {

    public InvalidFileException(String reason) {
        super(
                "Invalid file upload. " + reason,
                "File validation failed: " + reason,
                "INVALID_FILE");
    }
}
