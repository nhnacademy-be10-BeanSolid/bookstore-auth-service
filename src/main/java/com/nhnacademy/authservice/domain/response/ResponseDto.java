package com.nhnacademy.authservice.domain.response;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ResponseDto<T> {
    private boolean success;
    private String message;
    private T data;
}
