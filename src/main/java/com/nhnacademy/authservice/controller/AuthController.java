package com.nhnacademy.authservice.controller;

import com.nhnacademy.authservice.controller.api.AuthApi;
import com.nhnacademy.authservice.dto.auth.request.LoginRequestDto;
import com.nhnacademy.authservice.dto.auth.request.PasswordVerificationRequestDto;
import com.nhnacademy.authservice.dto.auth.response.RefreshTokenResponseDto;
import com.nhnacademy.authservice.dto.auth.response.TokenParseResponseDto;
import com.nhnacademy.authservice.dto.dormantuser.request.DormantUserVerificationRequestDto;
import com.nhnacademy.authservice.service.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
@Slf4j
public class AuthController implements AuthApi {
    private final AuthService authService;

    @Override
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequestDto request) {
        return ResponseEntity.ok(authService.login(request.id(), request.password()));
    }

    @Override
    @PostMapping("/verify-password")
    public ResponseEntity<Boolean> verifyPassword(
            @RequestHeader("X-USER-ID") String userId,
            @RequestBody PasswordVerificationRequestDto request) {
        boolean isValid = authService.verifyPassword(userId, request.password());
        return ResponseEntity.ok(isValid);
    }

    @Override
    @PostMapping("/refresh")
    public ResponseEntity<RefreshTokenResponseDto> refreshToken(@RequestBody String request) {
        return ResponseEntity.ok(authService.refreshToken(request));
    }

    @Override
    @PostMapping("/validate")
    public ResponseEntity<Boolean> validateToken(@RequestBody String token) {
        return ResponseEntity.ok(authService.validateToken(token));
    }

    @Override
    @PostMapping("/parse")
    public ResponseEntity<TokenParseResponseDto> parseToken(@RequestBody String token) {
        return ResponseEntity.ok(authService.parseToken(token));
    }

    @Override
    @PostMapping("/dormant/verify")
    public ResponseEntity<Boolean> dormantVerify(@RequestBody DormantUserVerificationRequestDto dto){
        log.debug("DormantUserVerificationRequestDto: {}", dto);
        return ResponseEntity.ok(authService.verifyDormantUserCode(dto));
    }
}
