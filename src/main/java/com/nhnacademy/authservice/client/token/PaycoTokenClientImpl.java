package com.nhnacademy.authservice.client.token;

import com.nhnacademy.authservice.adapter.PaycoTokenClient;
import com.nhnacademy.authservice.domain.OAuth2TokenResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component("paycoTokenClient")
@RequiredArgsConstructor
public class PaycoTokenClientImpl implements OAuth2TokenClient {
    private final PaycoTokenClient paycoTokenClient;

    @Value("${payco.client-id}")
    private String clientId;
    @Value("${payco.client-secret}")
    private String clientSecret;
    @Value("${payco.redirect-uri}")
    private String redirectUri;

    @Override
    public OAuth2TokenResponse getToken(String code) {
        return paycoTokenClient.getToken(
                "authorization_code",
                clientId,
                clientSecret,
                redirectUri,
                code
        );
    }
}
