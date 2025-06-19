package com.nhnacademy.authservice.service;

import com.nhnacademy.authservice.domain.RefreshTokenResponseDto;
import org.springframework.security.core.userdetails.UserDetails;

public interface AuthService {
    UserDetails authentication(String username, String password);

    RefreshTokenResponseDto refreshToken(String refreshToken);
}
