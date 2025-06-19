package com.nhnacademy.authservice.service;

import com.nhnacademy.authservice.domain.LoginResponseDto;
import com.nhnacademy.authservice.domain.RefreshTokenResponseDto;
import com.nhnacademy.authservice.domain.TokenParseResponseDto;
import org.springframework.security.core.userdetails.UserDetails;

public interface AuthService {
    LoginResponseDto login(String id, String password);

    UserDetails authentication(String username, String password);

    RefreshTokenResponseDto refreshToken(String refreshToken);

    boolean validateToken(String token);

    TokenParseResponseDto parseToken(String token);
}
