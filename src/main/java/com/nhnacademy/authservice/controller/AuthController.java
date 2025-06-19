package com.nhnacademy.authservice.controller;

import com.nhnacademy.authservice.domain.LoginRequestDto;
import com.nhnacademy.authservice.domain.RefreshTokenRequestDto;
import com.nhnacademy.authservice.domain.RefreshTokenResponseDto;
import com.nhnacademy.authservice.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {
    private final AuthService authService;

    // 로그인 API
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequestDto request) {
        return ResponseEntity.ok(authService.login(request.id(), request.password()));
    }

    @PostMapping("/refresh")
    public ResponseEntity<RefreshTokenResponseDto> refreshToken(@RequestBody RefreshTokenRequestDto request) {
        return ResponseEntity.ok(authService.refreshToken(request.refreshToken()));
    }

}
