package com.nhnacademy.authservice.controller;

import com.nhnacademy.authservice.controller.api.OAuth2Api;
import com.nhnacademy.authservice.dto.oauth2.request.OAuth2AdditionalSignupRequestDto;
import com.nhnacademy.authservice.dto.oauth2.request.OAuth2LoginRequestDto;
import com.nhnacademy.authservice.dto.oauth2.response.OAuth2LoginResponseDto;
import com.nhnacademy.authservice.dto.oauth2.response.ResponseDto;
import com.nhnacademy.authservice.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/oauth2")
public class OAuth2Controller implements OAuth2Api {
    private final AuthService authService;

    @Override
    @PostMapping("/login")
    public ResponseEntity<ResponseDto<?>> oauth2Login(@RequestBody OAuth2LoginRequestDto request) {
        return ResponseEntity.ok(authService.oauth2Login(request.getProvider(), request.getCode()));
    }

    @Override
    @PostMapping("/signup")
    public ResponseEntity<OAuth2LoginResponseDto> additionalSignup(
            @Valid @RequestBody OAuth2AdditionalSignupRequestDto request) {
        OAuth2LoginResponseDto response = authService.completeOAuth2Signup(request.getTempJwt(), request);
        return ResponseEntity.ok(response);
    }
}
