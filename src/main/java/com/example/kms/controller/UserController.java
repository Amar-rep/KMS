package com.example.kms.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestBody;
import com.example.kms.dto.RegisterUserDTO;
import com.example.kms.entity.AppUser;
import com.example.kms.service.UserService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/kms/users")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody RegisterUserDTO request) {
        userService.registerUser(request);
        return ResponseEntity.ok("User registered successfully");
    }

    @GetMapping("/{userIdKeccak}")
    public ResponseEntity<AppUser> getUserByKeccak(@PathVariable String userIdKeccak) {
        return ResponseEntity.ok(userService.findByKeccak(userIdKeccak));
    }

}
