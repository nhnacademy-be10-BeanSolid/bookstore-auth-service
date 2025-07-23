package com.nhnacademy.authservice.advice;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.Map;

@Data
public class ErrorResponseDto {
    @Schema(description = "HTTP 상태 코드", example = "400")
    private int status;
    @Schema(description = "오류 메시지", example = "입력 값 유효성 검사에 실패했습니다.")
    private String message;
    @Schema(description = "오류 발생 시간", example = "2025-07-22T10:48:17.123")
    private LocalDateTime time;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @Schema(description = "필드별 유효성 검사 오류 (MethodArgumentNotValidException 발생 시)", example = "{\"fieldName\": \"errorMessage\"}")
    private Map<String, String> errors;

    public ErrorResponseDto(int status, String message, LocalDateTime time) {
        this.status = status;
        this.message = message;
        this.time = time;
    }

    public ErrorResponseDto(int status, String message, LocalDateTime time, Map<String, String> errors) {
        this.status = status;
        this.message = message;
        this.time = time;
        this.errors = errors;
    }
}