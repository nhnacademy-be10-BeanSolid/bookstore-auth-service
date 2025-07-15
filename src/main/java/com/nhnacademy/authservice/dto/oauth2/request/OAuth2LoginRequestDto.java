package com.nhnacademy.authservice.dto.oauth2.request;

import lombok.Data;

@Data
public class OAuth2LoginRequestDto {
    private String provider;
    private String code;
}
