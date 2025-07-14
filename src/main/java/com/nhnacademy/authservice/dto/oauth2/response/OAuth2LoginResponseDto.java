package com.nhnacademy.authservice.dto.oauth2.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class OAuth2LoginResponseDto {
    private String accessToken;
    private String refreshToken;
}
