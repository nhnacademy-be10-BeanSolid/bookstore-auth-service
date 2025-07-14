package com.nhnacademy.authservice.dto.oauth2.response;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ResponseDto<T> {
    private boolean success;
    private String message;
    private T data;
}
