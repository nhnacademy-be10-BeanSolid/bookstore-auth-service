package com.nhnacademy.authservice.domain.request;

public record LoginRequestDto(
        String id,
        String password
) {
}
