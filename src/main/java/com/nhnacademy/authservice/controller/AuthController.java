package com.nhnacademy.authservice.controller;

import com.nhnacademy.authservice.domain.LoginRequestDto;
import com.nhnacademy.authservice.domain.LoginResponseDto;
import com.nhnacademy.authservice.provider.JwtTokenProvider;
import com.nhnacademy.authservice.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {
    private final AuthService authService;
    private final JwtTokenProvider jwtTokenProvider;

    // 로그인 API
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequestDto request) {
        // 1. AuthService에 인증 수행
        UserDetails userDetails = authService.authentication(request.id(), request.password());

        // 2. JWT 토큰 생성
        String accessToken = jwtTokenProvider.generateToken(userDetails);
        String refreshToken = jwtTokenProvider.generateRefreshToken(userDetails);

        // 3. 응답 반환
        return ResponseEntity.ok(
                new LoginResponseDto(accessToken, refreshToken)
        );
    }

}
