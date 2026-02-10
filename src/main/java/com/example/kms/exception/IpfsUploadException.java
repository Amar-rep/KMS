package com.example.kms.exception;

/**
 * Exception thrown when uploading to IPFS fails.
 */
public class IpfsUploadException extends KmsException {

    public IpfsUploadException(String developerMessage, Throwable cause) {
        super(
                "Failed to upload document to storage. .",
                developerMessage,
                "IPFS_UPLOAD_ERROR",
                cause);
    }
}
