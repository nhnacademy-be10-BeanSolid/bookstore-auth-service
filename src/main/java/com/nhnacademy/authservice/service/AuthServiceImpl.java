package com.nhnacademy.authservice.service;

import com.nhnacademy.authservice.domain.LoginResponseDto;
import com.nhnacademy.authservice.domain.RefreshTokenResponseDto;
import com.nhnacademy.authservice.exception.InvalidTokenException;
import com.nhnacademy.authservice.provider.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

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
        // 1. 인증 토큰 생성
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);

        // 2. AuthenticationManager를 통해 인증 시도
        Authentication authentication = authenticationManager.authenticate(authenticationToken);

        // 3. 인증 성공 시 UserDetails 반환
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
}
