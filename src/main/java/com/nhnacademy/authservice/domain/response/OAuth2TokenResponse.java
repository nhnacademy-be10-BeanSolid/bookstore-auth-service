package com.nhnacademy.authservice.domain.response;

import lombok.Data;

@Data
public class OAuth2TokenResponse {
    private String access_token;
    private String access_token_secret;
    private String refresh_token;
    private String token_type;
    private String expires_in;
    private String state;
}
