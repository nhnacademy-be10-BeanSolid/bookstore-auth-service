package com.nhnacademy.authservice.dto.auth.request;

import io.swagger.v3.oas.annotations.media.Schema;

public record LoginRequestDto(
        @Schema(description = "사용자 아이디", example = "testuser")
        String id,
        @Schema(description = "사용자 비밀번호", example = "password123")
        String password
) {
}