package com.nhnacademy.authservice.dto.dormantuser.request;

import io.swagger.v3.oas.annotations.media.Schema;

public record DormantUserVerificationRequestDto(
        @Schema(description = "휴면 사용자 ID", example = "dormantUser")
        String userId,
        @Schema(description = "휴면 해제 인증 코드", example = "123456")
        String verificationCode
){
}