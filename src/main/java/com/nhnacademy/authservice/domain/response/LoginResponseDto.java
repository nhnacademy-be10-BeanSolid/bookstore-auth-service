package com.nhnacademy.authservice.domain.response;

public record LoginResponseDto(
        String accessToken,
        String refreshToken
) {
}
