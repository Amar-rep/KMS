package com.example.kms.service;

import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.stereotype.Service;

import com.example.kms.dto.RegisterUserDTO;
import com.example.kms.entity.AppUser;
import com.example.kms.repository.AppUserRepository;

import lombok.RequiredArgsConstructor;
import java.util.Base64;

@Service
@RequiredArgsConstructor
public class UserService {

    private final AppUserRepository userRepository;

    public AppUser registerUser(RegisterUserDTO dto) {
        // Validate input
        if (dto.getPublicKeyBase64() == null || dto.getPublicKeyBase64().trim().isEmpty()) {
            throw new IllegalArgumentException("Public key is required");
        }

        try {
            // 1. Decode the incoming Base64 public key to bytes
            byte[] publicKeyBytes = Base64.getDecoder().decode(dto.getPublicKeyBase64());

            // 2. Calculate Keccak-256 hash of the public key
            Keccak.Digest256 digest256 = new Keccak.Digest256();
            byte[] hashBytes = digest256.digest(publicKeyBytes);

            // 3. Convert hash to Hex String (VARCHAR 64)
            String userIdKeccak = Hex.toHexString(hashBytes);

            // 4. Check if user already exists
            if (userRepository.findByUserIdKeccak(userIdKeccak).isPresent()) {
                throw new RuntimeException("User with this public key already exists");
            }

            // 5. Map to Entity
            AppUser user = new AppUser();
            user.setUserIdKeccak(userIdKeccak);
            user.setPublicKey(publicKeyBytes);
            user.setName(dto.getName());
            user.setPhysicalAddress(dto.getPhysicalAddress());
            user.setPhone(dto.getPhoneNumber());

            return userRepository.save(user);

        } catch (IllegalArgumentException e) {
            // Handle Base64 decoding errors or validation errors
            if (e.getMessage().contains("Illegal base64")) {
                throw new IllegalArgumentException("Invalid Base64 encoding in public key", e);
            }
            throw e; // Re-throw validation errors
        } catch (Exception e) {
            throw new RuntimeException("Failed to register user: " + e.getMessage(), e);
        }
    }

    public AppUser findByKeccak(String userIdKeccak) {
        return userRepository.findByUserIdKeccak(userIdKeccak)
                .orElseThrow(() -> new RuntimeException("User not found with keccak ID: " + userIdKeccak));
    }
}