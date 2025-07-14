package com.nhnacademy.authservice.dto.oauth2.response;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class OAuth2TokenResponse {
    private String access_token;
    private String access_token_secret;
    private String refresh_token;
    private String token_type;
    private String expires_in;
    private String state;
}
