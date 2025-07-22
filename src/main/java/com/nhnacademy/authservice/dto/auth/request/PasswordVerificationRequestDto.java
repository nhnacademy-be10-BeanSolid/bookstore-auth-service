package com.nhnacademy.authservice.dto.auth.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

public record PasswordVerificationRequestDto (
        @NotBlank(message = "비밀번호는 필수입니다.")
        @Schema(description = "확인할 비밀번호", example = "testpassword")
        String password
){
}