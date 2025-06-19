package com.nhnacademy.authservice.provider;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtTokenProviderTest {
    private JwtTokenProvider jwtTokenProvider;

    @Mock
    private UserDetails userDetails;

    @BeforeEach
    void setUp() {
        byte[] randomKey = new byte[32];
        new SecureRandom().nextBytes(randomKey);
        String secretKey = Base64.getEncoder().encodeToString(randomKey);
        jwtTokenProvider = new JwtTokenProvider(secretKey);
    }

    @Test
    @DisplayName("액세스 토큰 생성 및 검증")
    void testGenerateAndValidateAccessToken() {
        when(userDetails.getUsername()).thenReturn("testuser");
        when(userDetails.getAuthorities()).thenReturn(Collections.emptyList());

        String token = jwtTokenProvider.generateToken(userDetails);

        assertNotNull(token);
        assertTrue(jwtTokenProvider.validateToken(token));
        assertEquals("testuser", jwtTokenProvider.getUsernameFromToken(token));
    }

    @Test
    @DisplayName("리프레시 토큰 생성 및 검증")
    void testGenerateAndValidateRefreshToken() {
        when(userDetails.getUsername()).thenReturn("testuser");

        String refreshToken = jwtTokenProvider.generateRefreshToken(userDetails);

        assertNotNull(refreshToken);
        assertTrue(jwtTokenProvider.validateToken(refreshToken));
        assertEquals("testuser", jwtTokenProvider.getUsernameFromToken(refreshToken));
    }

    @Test
    @DisplayName("잘못된 토큰 검증 실패")
    void testInvalidToken() {
        String invalidToken = "invalid.token.value";
        assertFalse(jwtTokenProvider.validateToken(invalidToken));
    }
}