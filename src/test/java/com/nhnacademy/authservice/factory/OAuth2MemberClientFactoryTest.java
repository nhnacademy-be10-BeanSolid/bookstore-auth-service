package com.nhnacademy.authservice.factory;

import com.nhnacademy.authservice.client.member.OAuth2MemberClient;
import com.nhnacademy.authservice.domain.response.OAuth2MemberResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.stereotype.Component;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class OAuth2MemberClientFactoryTest {

    @Component("kakaoMemberClient")
    static class KakaoMemberClient implements OAuth2MemberClient {
        @Override
        public OAuth2MemberResponse getMember(String accessToken) {
            return null;
        }
    }
    @Component("naverMemberClient")
    static class NaverMemberClient implements OAuth2MemberClient {
        @Override
        public OAuth2MemberResponse getMember(String accessToken) {
            return null;
        }
    }

    private OAuth2MemberClientFactory factory;

    @BeforeEach
    void setUp() {
        factory = new OAuth2MemberClientFactory(List.of(
                new KakaoMemberClient(),
                new NaverMemberClient()
        ));
    }

    @Test
    @DisplayName("등록된 provider 이름으로 올바른 MemberClient 반환")
    void testGetClientReturnsCorrectInstance() {
        OAuth2MemberClient kakao = factory.getClient("kakao");
        assertNotNull(kakao);
        assertInstanceOf(KakaoMemberClient.class, kakao);

        OAuth2MemberClient naver = factory.getClient("naver");
        assertNotNull(naver);
        assertInstanceOf(NaverMemberClient.class, naver);
    }

    @Test
    @DisplayName("등록되지 않은 provider 요청 시 null 반환")
    void testGetClientWithUnknownProviderReturnsNull() {
        OAuth2MemberClient unknown = factory.getClient("google");
        assertNull(unknown);
    }
}