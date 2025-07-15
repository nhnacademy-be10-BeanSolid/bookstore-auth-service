package com.nhnacademy.authservice.advice;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.Map;

@Data
public class ErrorResponseDto {
    private int status;
    private String message;
    private LocalDateTime time;

    @JsonInclude(JsonInclude.Include.NON_NULL)
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
