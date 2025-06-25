package com.nhnacademy.authservice.service;

import com.nhnacademy.authservice.domain.LoginResponseDto;
import com.nhnacademy.authservice.domain.RefreshTokenResponseDto;
import com.nhnacademy.authservice.domain.TokenParseResponseDto;
import com.nhnacademy.authservice.exception.InvalidTokenException;
import com.nhnacademy.authservice.provider.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final JwtTokenProvider jwtTokenProvider;

    @Override
    public LoginResponseDto login(String id, String password) {
        UserDetails userDetails = authentication(id, password);
        String accessToken = jwtTokenProvider.generateToken(userDetails);
        String refreshToken = jwtTokenProvider.generateRefreshToken(userDetails);
        return new LoginResponseDto(accessToken, refreshToken);
    }


    @Override
    public UserDetails authentication(String username, String password) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password));
        return (UserDetails) authentication.getPrincipal();
    }

    @Override
    public RefreshTokenResponseDto refreshToken(String refreshToken) {
        // 1. RefreshToken 유효성 검증
        if(!jwtTokenProvider.validateToken(refreshToken)) {
            throw new InvalidTokenException("Invalid Refresh Token");
        }

        // 2. RefreshToken 사용자 정보 추출
        String username = jwtTokenProvider.getUsernameFromToken(refreshToken);

        // 3. 사용자 정보로 UserDetails 조회
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        // 4. 새 AccessToken 및 RefreshToken 발급
        String newAccessToken = jwtTokenProvider.generateToken(userDetails);
        String newRefreshToken = jwtTokenProvider.generateRefreshToken(userDetails);

        // 5. 응답 반환
        return new RefreshTokenResponseDto(newAccessToken, newRefreshToken);
    }

    @Override
    public boolean validateToken(String token) {
        return jwtTokenProvider.validateToken(token);
    }

    @Override
    public TokenParseResponseDto parseToken(String token) {
        // 1. 반드시 유효성 검증
        if (!jwtTokenProvider.validateToken(token)) {
            throw new InvalidTokenException("Invalid Token");
        }
        String username = jwtTokenProvider.getUsernameFromToken(token);
        List<String> authorities = jwtTokenProvider.getAuthoritiesFromToken(token);
        return new TokenParseResponseDto(username, authorities);
    }
}
