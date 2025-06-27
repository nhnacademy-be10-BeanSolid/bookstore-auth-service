package com.nhnacademy.authservice.domain;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class OAuth2LoginResponseDto {
    private String accessToken;
    private String refreshToken;
}
