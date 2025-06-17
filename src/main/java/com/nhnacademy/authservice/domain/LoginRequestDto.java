package com.nhnacademy.authservice.domain;

public record LoginRequestDto(
        String id,
        String password
) {
}
