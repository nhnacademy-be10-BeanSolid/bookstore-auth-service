package com.nhnacademy.authservice.dto.auth.response;

public record LoginResponseDto(
        String accessToken,
        String refreshToken
) {
}
