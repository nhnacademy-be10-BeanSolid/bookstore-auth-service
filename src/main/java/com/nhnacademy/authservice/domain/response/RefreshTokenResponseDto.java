package com.nhnacademy.authservice.domain.response;

public record RefreshTokenResponseDto(
        String accessToken,
        String refreshToken
) {
}
