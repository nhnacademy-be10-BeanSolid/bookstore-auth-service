package com.nhnacademy.authservice.dto.auth.response;

import com.nhnacademy.authservice.provider.UserType;
import io.swagger.v3.oas.annotations.media.Schema;

import java.util.List;

public record TokenParseResponseDto(
        @Schema(description = "토큰에서 추출된 사용자 이름", example = "testuser")
        String username,
        @Schema(description = "토큰에서 추출된 사용자 권한 목록", example = "[\"ROLE_USER\", \"ROLE_ADMIN\"]")
        List<String> authorities,
        @Schema(description = "토큰에서 추출된 사용자 유형", example = "LOCAL")
        UserType userType
) {
}