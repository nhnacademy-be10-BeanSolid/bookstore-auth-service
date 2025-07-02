package com.nhnacademy.authservice.client.token;

import com.nhnacademy.authservice.domain.response.OAuth2TokenResponse;

public interface OAuth2TokenClient {
    OAuth2TokenResponse getToken(String code);
}
