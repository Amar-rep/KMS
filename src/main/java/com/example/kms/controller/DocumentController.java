package com.example.kms.controller;

import com.example.kms.dto.*;
import com.example.kms.service.FileService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/api/files")
@RequiredArgsConstructor
public class DocumentController {

    private final FileService fileService;

    /**
     * POST /api/files/upload
     * Upload and encrypt a file, store in IPFS
     * Accepts JSON with Base64-encoded file data
     * 
     * @param uploadFileDTO DTO containing Base64 file data and all upload
     *                      parameters
     * @return UploadResponseDTO containing CID, record ID, and group ID
     */
    @PostMapping("/upload")
    public ResponseEntity<UploadResponseDTO> uploadFile(@RequestBody UploadFileDTO uploadFileDTO) {
        try {
            log.info("Processing file upload from {} to group {}",
                    uploadFileDTO.getSender_keccak(), uploadFileDTO.getGroup_id());

            // Call service
            UploadResponseDTO response = fileService.uploadFile(uploadFileDTO);

            log.info("File uploaded successfully: CID={}, RecordID={}",
                    response.getCid(), response.getRecordId());
            return ResponseEntity.status(HttpStatus.CREATED).body(response);

        } catch (Exception e) {
            log.error("File upload failed", e);
            throw e;
        }
    }

    /**
     * POST /api/files/download
     * Download and decrypt a file from IPFS
     * 
     * @param downloadFileDTO Request containing sender info, group ID, record ID,
     *                        and authentication
     * @return Decrypted file as byte array with appropriate headers
     */
    @PostMapping("/download")
    public ResponseEntity<byte[]> downloadFile(@RequestBody DownloadFileDTO downloadFileDTO) {
        try {
            log.info("Processing file download request for record: {}", downloadFileDTO.getRecordId());

            // Call service
            DownloadResponseDTO response = fileService.downloadFile(downloadFileDTO);

            // Set headers for file download
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
            headers.setContentDispositionFormData("attachment", "file_" + response.getRecordId());
            headers.setContentLength(response.getFileData().length);

            log.info("File downloaded successfully: RecordID={}, Size={} bytes",
                    response.getRecordId(), response.getFileData().length);

            return ResponseEntity.ok()
                    .headers(headers)
                    .body(response.getFileData());

        } catch (Exception e) {
            log.error("File download failed", e);
            throw e;
        }
    }

    /**
     * POST /api/files/allow-access
     * Grant access to a group by encrypting the group key with receiver's public
     * key
     * 
     * @param allowAccessDTO Request containing sender, receiver, group info, and
     *                       authentication
     * @return AllowAccessResponseDTO containing encrypted group key for the
     *         receiver
     */
    @PostMapping("/allow-access")
    public ResponseEntity<AllowAccessResponseDTO> allowAccess(@RequestBody AllowAccessDTO allowAccessDTO) {
        try {
            log.info("Processing access grant request from {} to {} for group {}",
                    allowAccessDTO.getSender_keccak(),
                    allowAccessDTO.getReceiver_keccak(),
                    allowAccessDTO.getGroupId());

            // Call service
            AllowAccessResponseDTO response = fileService.allowAccess(allowAccessDTO);

            log.info("Access granted successfully to {} for group {}",
                    response.getReceiverKeccak(), response.getGroupId());

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Allow access failed", e);
            throw e;
        }
    }
}
