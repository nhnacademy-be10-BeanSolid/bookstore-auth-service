package com.nhnacademy.authservice.dto.auth.response;

public record RefreshTokenResponseDto(
        String accessToken,
        String refreshToken
) {
}
