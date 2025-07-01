package com.nhnacademy.authservice.service;

import com.nhnacademy.authservice.domain.response.LoginResponseDto;
import com.nhnacademy.authservice.domain.response.RefreshTokenResponseDto;
import com.nhnacademy.authservice.domain.response.TokenParseResponseDto;
import com.nhnacademy.authservice.exception.InvalidTokenException;
import com.nhnacademy.authservice.provider.JwtTokenProvider;
import com.nhnacademy.authservice.service.auth.AuthServiceImpl;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceImplTest {
    @Mock
    AuthenticationManager authenticationManager;

    @Mock
    UserDetailsService userDetailsService;

    @Mock
    JwtTokenProvider jwtTokenProvider;

    @InjectMocks
    AuthServiceImpl authService;

    @Mock
    UserDetails userDetails;

    @Mock
    Authentication authentication;

    @Test
    void login_success() {
        String id = "user";
        String pw = "pw";
        String accessToken = "access-token";
        String refreshToken = "refresh-token";

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(userDetails);
        when(jwtTokenProvider.generateToken(userDetails)).thenReturn(accessToken);
        when(jwtTokenProvider.generateRefreshToken(userDetails)).thenReturn(refreshToken);

        LoginResponseDto result = authService.login(id, pw);

        assertEquals(accessToken, result.accessToken());
        assertEquals(refreshToken, result.refreshToken());
    }

    @Test
    void authentication_success() {
        String username = "user";
        String password = "pw";
        when(authenticationManager.authenticate(any())).thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(userDetails);

        UserDetails result = authService.authentication(username, password);

        assertEquals(userDetails, result);
    }

    @Test
    void refreshToken_success() {
        String refreshToken = "refresh-token";
        String username = "user";
        String newAccessToken = "new-access";
        String newRefreshToken = "new-refresh";

        when(jwtTokenProvider.validateToken(refreshToken)).thenReturn(true);

        when(jwtTokenProvider.getUsernameFromToken(refreshToken)).thenReturn(username);
        when(userDetailsService.loadUserByUsername(username)).thenReturn(userDetails);

        when(jwtTokenProvider.generateToken(userDetails)).thenReturn(newAccessToken);
        when(jwtTokenProvider.generateRefreshToken(userDetails)).thenReturn(newRefreshToken);

        RefreshTokenResponseDto result = authService.refreshToken(refreshToken);

        assertEquals(newAccessToken, result.accessToken());
        assertEquals(newRefreshToken, result.refreshToken());
    }

    @Test
    void refreshToken_invalidToken_throwsException() {
        String refreshToken = "invalid";
        when(jwtTokenProvider.validateToken(refreshToken)).thenReturn(false);

        assertThrows(InvalidTokenException.class, () ->
                authService.refreshToken(refreshToken));
    }

    @Test
    void validateToken_success() {
        String token = "token";
        when(jwtTokenProvider.validateToken(token)).thenReturn(true);

        assertTrue(authService.validateToken(token));
    }

    @Test
    void parseToken_success() {
        String token = "valid-token";
        String username = "testuser";
        List<String> authorities = List.of("ROLE_USER", "ROLE_ADMIN");

        when(jwtTokenProvider.validateToken(token)).thenReturn(true);
        when(jwtTokenProvider.getUsernameFromToken(token)).thenReturn(username);
        when(jwtTokenProvider.getAuthoritiesFromToken(token)).thenReturn(authorities);

        TokenParseResponseDto result = authService.parseToken(token);

        assertEquals(username, result.username());
        assertEquals(authorities, result.authorities());
    }

    @Test
    void parseToken_invalidToken_throwsException() {
        String token = "invalid-token";
        when(jwtTokenProvider.validateToken(token)).thenReturn(false);

        assertThrows(InvalidTokenException.class, () -> authService.parseToken(token));
    }
}