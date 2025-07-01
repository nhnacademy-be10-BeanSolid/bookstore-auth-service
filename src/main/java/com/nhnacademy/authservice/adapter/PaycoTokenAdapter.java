package com.nhnacademy.authservice.adapter;

import com.nhnacademy.authservice.domain.response.OAuth2TokenResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@FeignClient(name = "paycoTokenClient", url = "https://id.payco.com")
public interface PaycoTokenAdapter {
    @PostMapping(value = "/oauth2.0/token", consumes = "application/x-www-form-urlencoded")
    OAuth2TokenResponse getToken(
            @RequestParam("grant_type") String grantType,
            @RequestParam("client_id") String clientId,
            @RequestParam("client_secret") String clientSecret,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam("code") String code
    );
}
