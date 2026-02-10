package com.example.kms.exception;

/**
 * Exception thrown when fetching from IPFS fails.
 */
public class IpfsFetchException extends KmsException {

    public IpfsFetchException(String cid, Throwable cause) {
        super(
                "Failed to retrieve document from storage.",
                String.format("Failed to fetch CID '%s' from IPFS", cid),
                "IPFS_FETCH_ERROR",
                cause);
    }
}
