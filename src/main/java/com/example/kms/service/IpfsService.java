package com.example.kms.service;

import com.example.kms.exception.IpfsConnectionException;
import com.example.kms.exception.IpfsFetchException;
import com.example.kms.exception.IpfsUploadException;
import io.ipfs.api.IPFS;
import io.ipfs.api.MerkleNode;
import io.ipfs.api.NamedStreamable;
import io.ipfs.multihash.Multihash;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class IpfsService {

    @Value("${ipfs.api.host:127.0.0.1}")
    private String ipfsApiHost;

    @Value("${ipfs.api.port:5001}")
    private int ipfsApiPort;

    private IPFS ipfs;

    /**
     * Lazy initialization of IPFS client.
     * Only connects when first needed, not at startup.
     */
    private IPFS getIpfs() {
        if (ipfs == null) {
            try {
                // IPFS client expects MultiAddress format: /ip4/127.0.0.1/tcp/5001
                String multiAddress = String.format("/ip4/%s/tcp/%d", ipfsApiHost, ipfsApiPort);
                log.info("Connecting to IPFS at: {}", multiAddress);
                ipfs = new IPFS(multiAddress);
            } catch (Exception e) {
                log.error("Failed to initialize IPFS client with host: {}, port: {}", ipfsApiHost, ipfsApiPort, e);
                throw new IpfsConnectionException(
                        String.format("Failed to connect to IPFS at %s:%d - %s", ipfsApiHost, ipfsApiPort,
                                e.getMessage()),
                        e);
            }
        }
        return ipfs;
    }

    /**
     * Uploads data to IPFS and returns the CID.
     */
    public String upload(byte[] data) {
        try {
            log.debug("Uploading {} bytes to IPFS", data.length);
            NamedStreamable.ByteArrayWrapper file = new NamedStreamable.ByteArrayWrapper(data);
            MerkleNode addResult = getIpfs().add(file).get(0);
            String cid = addResult.hash.toString();
            log.info("Successfully uploaded to IPFS with CID: {}", cid);
            return cid;
        } catch (IpfsConnectionException e) {
            throw e; // Re-throw connection exceptions
        } catch (Exception e) {
            log.error("Failed to upload data to IPFS", e);
            throw new IpfsUploadException("Error uploading data to IPFS: " + e.getMessage(), e);
        }
    }

    /**
     * Fetches data from IPFS by CID.
     */
    public byte[] fetch(String cid) {
        try {
            log.debug("Fetching CID from IPFS: {}", cid);
            Multihash filePointer = Multihash.fromBase58(cid);
            byte[] data = getIpfs().cat(filePointer);
            log.info("Successfully fetched {} bytes from IPFS for CID: {}", data.length, cid);
            return data;
        } catch (IpfsConnectionException e) {
            throw e; // Re-throw connection exceptions
        } catch (Exception e) {
            log.error("Failed to fetch CID '{}' from IPFS", cid, e);
            throw new IpfsFetchException(cid, e);
        }
    }
}
