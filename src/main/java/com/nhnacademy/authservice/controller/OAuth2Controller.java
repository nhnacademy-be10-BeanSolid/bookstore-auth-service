package com.nhnacademy.authservice.controller;

import com.nhnacademy.authservice.domain.OAuth2LoginRequestDto;
import com.nhnacademy.authservice.domain.OAuth2LoginResponseDto;
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
    public ResponseEntity<OAuth2LoginResponseDto> oauth2Login(@RequestBody OAuth2LoginRequestDto request) {
        return ResponseEntity.ok(authService.oauth2Login(request.getProvider(), request.getCode()));
    }
}
