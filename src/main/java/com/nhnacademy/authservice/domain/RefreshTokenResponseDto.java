package com.nhnacademy.authservice.domain;

public record RefreshTokenResponseDto(
        String accessToken,
        String refreshToken
) {
}
