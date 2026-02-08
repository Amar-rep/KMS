# Exception Handling System - KMS Project

## Overview
A comprehensive exception handling system has been implemented for the KMS (Key Management System) project. This system provides:
- **User-friendly error messages** for end users
- **Detailed developer messages** for debugging (when debug mode is enabled)
- **Structured error responses** with consistent format
- **Proper HTTP status codes** for different error scenarios
- **Comprehensive logging** for all exceptions

## Architecture

### 1. Base Exception Class
**File:** `KmsException.java`

The base exception class that all custom exceptions extend from. It contains:
- `userMessage`: User-friendly message shown to end users
- `developerMessage`: Technical details for developers
- `errorCode`: Unique error code for tracking and categorization

### 2. Custom Exception Classes

#### IpfsConnectionException
- **Error Code:** `IPFS_CONNECTION_ERROR`
- **HTTP Status:** 503 (Service Unavailable)
- **Use Case:** IPFS connection failures, invalid MultiAddress format
- **User Message:** "Unable to connect to storage service. Please try again later."

#### IpfsUploadException
- **Error Code:** `IPFS_UPLOAD_ERROR`
- **HTTP Status:** 500 (Internal Server Error)
- **Use Case:** Failures during IPFS upload operations
- **User Message:** "Failed to upload document to storage. Please try again."

#### IpfsFetchException
- **Error Code:** `IPFS_FETCH_ERROR`
- **HTTP Status:** 500 (Internal Server Error)
- **Use Case:** Failures when fetching data from IPFS
- **User Message:** "Failed to retrieve document from storage. The document may not exist or the service is unavailable."

#### EncryptionException
- **Error Code:** `ENCRYPTION_ERROR`
- **HTTP Status:** 500 (Internal Server Error)
- **Use Case:** AES encryption failures
- **User Message:** "Failed to encrypt document. Please try again."

#### DecryptionException
- **Error Code:** `DECRYPTION_ERROR`
- **HTTP Status:** 500 (Internal Server Error)
- **Use Case:** AES decryption failures, invalid keys
- **User Message:** "Failed to decrypt document. The encryption key may be invalid or the document is corrupted."

#### InvalidFileException
- **Error Code:** `INVALID_FILE`
- **HTTP Status:** 400 (Bad Request)
- **Use Case:** Invalid file uploads, file reading errors
- **User Message:** "Invalid file upload. [reason]"

### 3. Global Exception Handler
**File:** `GlobalExceptionHandler.java`

A centralized exception handler using `@RestControllerAdvice` that catches all exceptions and returns standardized error responses.

#### Handled Exception Types:
1. **KmsException** - All custom KMS exceptions
2. **IpfsConnectionException** - IPFS connection issues (503)
3. **InvalidFileException** - Invalid file uploads (400)
4. **MaxUploadSizeExceededException** - File size exceeded (413)
5. **MultipartException** - Multipart request errors (400)
6. **IllegalArgumentException** - Invalid arguments (400)
7. **Exception** - Catch-all for unhandled exceptions (500)

### 4. Error Response DTO
**File:** `ErrorResponseDTO.java`

Standardized error response structure:
```json
{
  "timestamp": "2026-02-05T20:55:48",
  "status": 500,
  "error": "Internal Server Error",
  "message": "User-friendly error message",
  "errorCode": "IPFS_CONNECTION_ERROR",
  "path": "/upload",
  "developerMessage": "Detailed technical message (only in debug mode)"
}
```

## Configuration

### Debug Mode
Set in `application.properties`:
```properties
kms.debug-mode=true
```

- **When enabled:** Developer messages are included in error responses
- **When disabled:** Only user-friendly messages are returned (recommended for production)

### IPFS Configuration
```properties
ipfs.api.host=127.0.0.1
ipfs.api.port=5001
```

**Important:** Use IP address (127.0.0.1) instead of hostname (localhost) to avoid MultiAddress format errors.

## Service Layer Updates

### IpfsService
- Added try-catch blocks around IPFS operations
- Throws `IpfsConnectionException` for connection failures
- Throws `IpfsUploadException` for upload failures
- Throws `IpfsFetchException` for fetch failures
- Added comprehensive logging (debug and info levels)

### EncryptionService
- Added try-catch blocks around encryption/decryption operations
- Throws `EncryptionException` for encryption failures
- Throws `DecryptionException` for decryption failures
- Added comprehensive logging

### DocumentController
- Removed `throws Exception` from method signatures
- Added try-catch for `file.getBytes()` IOException
- Exceptions are now handled by the global exception handler

## Error Codes Reference

| Error Code | Description | HTTP Status |
|------------|-------------|-------------|
| IPFS_CONNECTION_ERROR | IPFS connection failure | 503 |
| IPFS_UPLOAD_ERROR | IPFS upload failure | 500 |
| IPFS_FETCH_ERROR | IPFS fetch failure | 500 |
| ENCRYPTION_ERROR | Encryption failure | 500 |
| DECRYPTION_ERROR | Decryption failure | 500 |
| INVALID_FILE | Invalid file upload | 400 |
| FILE_TOO_LARGE | File size exceeded | 413 |
| INVALID_MULTIPART_REQUEST | Invalid multipart request | 400 |
| INVALID_ARGUMENT | Invalid request parameters | 400 |
| INTERNAL_ERROR | Unhandled exception | 500 |

## Logging Strategy

### Log Levels:
- **ERROR:** Connection failures, encryption/decryption failures, unhandled exceptions
- **WARN:** Invalid files, file size exceeded, invalid arguments
- **INFO:** Successful operations (upload, fetch, encrypt, decrypt)
- **DEBUG:** Operation details (bytes processed, CIDs, etc.)

### Log Format:
```
ERROR - IPFS Connection Error: Failed to connect to IPFS at 127.0.0.1:5001 - Invalid IPv4 address: localhost
INFO  - Successfully uploaded to IPFS with CID: QmXyz...
DEBUG - Uploading 1024 bytes to IPFS
```

## Example Error Responses

### IPFS Connection Error (Debug Mode ON)
```json
{
  "timestamp": "2026-02-05T20:55:48",
  "status": 503,
  "error": "Service Unavailable",
  "message": "Unable to connect to storage service. Please try again later.",
  "errorCode": "IPFS_CONNECTION_ERROR",
  "path": "/upload",
  "developerMessage": "Failed to connect to IPFS at 127.0.0.1:5001 - Connection refused"
}
```

### Invalid File (Debug Mode OFF)
```json
{
  "timestamp": "2026-02-05T20:55:48",
  "status": 400,
  "error": "Bad Request",
  "message": "Invalid file upload. Unable to read file: Stream closed",
  "errorCode": "INVALID_FILE",
  "path": "/upload"
}
```

## Best Practices

1. **Production Deployment:**
   - Set `kms.debug-mode=false` to hide technical details from users
   - Monitor logs for detailed error information

2. **Development:**
   - Keep `kms.debug-mode=true` for easier debugging
   - Check logs for full stack traces

3. **Adding New Exceptions:**
   - Extend `KmsException` base class
   - Provide clear user and developer messages
   - Use descriptive error codes
   - Add handler in `GlobalExceptionHandler` if special handling needed

4. **Error Handling in Services:**
   - Catch specific exceptions first
   - Re-throw connection exceptions
   - Log errors before throwing custom exceptions
   - Include context in developer messages

## Files Created/Modified

### New Files:
- `exception/KmsException.java`
- `exception/IpfsConnectionException.java`
- `exception/IpfsUploadException.java`
- `exception/IpfsFetchException.java`
- `exception/EncryptionException.java`
- `exception/DecryptionException.java`
- `exception/InvalidFileException.java`
- `exception/GlobalExceptionHandler.java`
- `dto/ErrorResponseDTO.java`

### Modified Files:
- `service/IpfsService.java` - Added exception handling and logging
- `service/EncryptionService.java` - Added exception handling and logging
- `controller/DocumentController.java` - Removed throws declarations, added try-catch
- `resources/application.properties` - Added debug mode configuration
- `config/CorsConfig.java` - Previously created for CORS support

## Testing the Exception Handling

### Test IPFS Connection Error:
1. Stop IPFS daemon
2. Try to upload a file
3. Should receive 503 error with user-friendly message

### Test Invalid File:
1. Send malformed multipart request
2. Should receive 400 error

### Test File Too Large:
1. Configure max file size in application.properties
2. Upload file exceeding limit
3. Should receive 413 error

### Test Decryption Error:
1. Try to decrypt with wrong key
2. Should receive 500 error with decryption message
