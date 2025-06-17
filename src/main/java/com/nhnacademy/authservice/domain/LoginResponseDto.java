package com.nhnacademy.authservice.domain;

public record LoginResponseDto(
        String accessToken,
        String refreshToken
) {
}
