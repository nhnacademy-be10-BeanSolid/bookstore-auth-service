package com.nhnacademy.authservice.dto.auth.request;

public record LoginRequestDto(
        String id,
        String password
) {
}
