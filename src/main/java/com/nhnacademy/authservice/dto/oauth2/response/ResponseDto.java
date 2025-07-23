package com.nhnacademy.authservice.dto.oauth2.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ResponseDto<T> {
    @Schema(description = "요청 성공 여부", example = "true")
    private boolean success;
    @Schema(description = "응답 메시지", example = "로그인 성공")
    private String message;
    @Schema(description = "응답 데이터")
    private T data;
}