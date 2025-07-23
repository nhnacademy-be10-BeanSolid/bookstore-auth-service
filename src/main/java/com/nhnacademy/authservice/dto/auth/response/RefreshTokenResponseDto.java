package com.nhnacademy.authservice.dto.auth.response;

import io.swagger.v3.oas.annotations.media.Schema;

public record RefreshTokenResponseDto(
        @Schema(description = "새로 발급된 JWT Access Token", example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
        String accessToken,
        @Schema(description = "새로 발급된 JWT Refresh Token", example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
        String refreshToken
) {
}