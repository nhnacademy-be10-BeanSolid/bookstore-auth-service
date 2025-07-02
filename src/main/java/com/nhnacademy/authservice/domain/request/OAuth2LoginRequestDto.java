package com.nhnacademy.authservice.domain.request;

import lombok.Data;

@Data
public class OAuth2LoginRequestDto {
    private String provider;
    private String code;
}
