package com.nhnacademy.authservice.factory;

import com.nhnacademy.authservice.client.token.OAuth2TokenClient;
import com.nhnacademy.authservice.domain.response.OAuth2TokenResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.stereotype.Component;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class OAuth2TokenClientFactoryTest {

    @Component("kakaoTokenClient")
    static class KakaoTokenClient implements OAuth2TokenClient {
        @Override
        public OAuth2TokenResponse getToken(String code) {
            return null;
        }
    }
    @Component("naverTokenClient")
    static class NaverTokenClient implements OAuth2TokenClient {
        @Override
        public OAuth2TokenResponse getToken(String code) {
            return null;
        }
    }

    private OAuth2TokenClientFactory factory;

    @BeforeEach
    void setUp() {
        factory = new OAuth2TokenClientFactory(List.of(
                new KakaoTokenClient(),
                new NaverTokenClient()
        ));
    }

    @Test
    @DisplayName("등록된 provider 이름으로 올바른 TokenCleint 반환")
    void testGetClientReturnsCorrectInstance() {
        OAuth2TokenClient kakao = factory.getClient("kakao");
        assertNotNull(kakao);
        assertInstanceOf(KakaoTokenClient.class, kakao);

        OAuth2TokenClient naver = factory.getClient("naver");
        assertNotNull(naver);
        assertInstanceOf(NaverTokenClient.class, naver);
    }

    @Test
    @DisplayName("등록되지 않은 provider 요청 시 null 반환")
    void testGetClientWithUnknownProviderReturnsNull() {
        OAuth2TokenClient unknown = factory.getClient("google");
        assertNull(unknown);
    }

}