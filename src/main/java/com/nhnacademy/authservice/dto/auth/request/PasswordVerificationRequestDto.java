package com.nhnacademy.authservice.dto.auth.request;

import jakarta.validation.constraints.NotBlank;

public record PasswordVerificationRequestDto (
        @NotBlank(message = "비밀번호는 필수입니다.")
        String password
){
}
