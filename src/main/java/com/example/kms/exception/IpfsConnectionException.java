package com.example.kms.exception;

/**
 * Exception thrown when IPFS connection or operations fail.
 */
public class IpfsConnectionException extends KmsException {

    public IpfsConnectionException(String developerMessage, Throwable cause) {
        super(
                "Unable to connect to storage service. Please try again later.",
                developerMessage,
                "IPFS_CONNECTION_ERROR",
                cause);
    }

    public IpfsConnectionException(String developerMessage) {
        super(
                "Unable to connect to storage service. Please try again later.",
                developerMessage,
                "IPFS_CONNECTION_ERROR");
    }
}
