package com.nhnacademy.authservice.controller;

import com.nhnacademy.authservice.domain.request.OAuth2AdditionalSignupRequestDto;
import com.nhnacademy.authservice.domain.request.OAuth2LoginRequestDto;
import com.nhnacademy.authservice.domain.response.OAuth2LoginResponseDto;
import com.nhnacademy.authservice.domain.response.ResponseDto;
import com.nhnacademy.authservice.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/oauth2")
public class OAuth2Controller {
    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<ResponseDto<?>> oauth2Login(@RequestBody OAuth2LoginRequestDto request) {
        return ResponseEntity.ok(authService.oauth2Login(request.getProvider(), request.getCode()));
    }

    @PostMapping("/signup")
    public ResponseEntity<OAuth2LoginResponseDto> additionalSignup(
            @RequestBody OAuth2AdditionalSignupRequestDto request) {
        OAuth2LoginResponseDto response = authService.completeOAuth2Signup(request.getTempJwt(), request);
        return ResponseEntity.ok(response);
    }
}
