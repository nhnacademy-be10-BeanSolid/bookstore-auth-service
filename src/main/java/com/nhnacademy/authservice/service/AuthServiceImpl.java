package com.nhnacademy.authservice.service;

import com.nhnacademy.authservice.adapter.UserAdapter;
import com.nhnacademy.authservice.client.member.OAuth2MemberClient;
import com.nhnacademy.authservice.client.token.OAuth2TokenClient;
import com.nhnacademy.authservice.domain.*;
import com.nhnacademy.authservice.exception.InvalidTokenException;
import com.nhnacademy.authservice.factory.OAuth2MemberClientFactory;
import com.nhnacademy.authservice.factory.OAuth2TokenClientFactory;
import com.nhnacademy.authservice.provider.JwtTokenProvider;
import com.nhnacademy.authservice.userdetails.CustomUserDetails;
import feign.FeignException;
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

    private final OAuth2TokenClientFactory tokenClientFactory;
    private final OAuth2MemberClientFactory memberClientFactory;

    private final UserAdapter userAdapter;

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
        if (!jwtTokenProvider.validateToken(token)) {
            throw new InvalidTokenException("Invalid Token");
        }
        String username = jwtTokenProvider.getUsernameFromToken(token);
        List<String> authorities = jwtTokenProvider.getAuthoritiesFromToken(token);
        return new TokenParseResponseDto(username, authorities);
    }

    @Override
    public OAuth2LoginResponseDto oauth2Login(String provider, String code) {
        // 1. 토큰 발급
        OAuth2TokenClient tokenClient = tokenClientFactory.getClient(provider.toLowerCase());
        OAuth2TokenResponse tokenResponse = tokenClient.getToken(code);

        // 2. accessToken 으로 사용자 정보 조회
        OAuth2MemberClient memberClient = memberClientFactory.getClient(provider.toLowerCase());
        OAuth2MemberResponse memberResponse = memberClient.getMember(tokenResponse.getAccess_token());

        // 3. DB 에서 사용자 조회
        UserResponse userResponse = null;
        try {
            userResponse = userAdapter.getUserByUsername(provider.toUpperCase() + memberResponse.getData().getMember().getIdNo());
        } catch (FeignException e) {
            if(e.status() != 404) {
                throw e;
            }
        }

        // 4. 유저 정보가 없을 때: 임시 JWT 발급 & Redis에 OAuth2 유저 정보 저장
        if(userResponse == null) {
            // (1) 임시 JWT 생성 (payload 에는 provider, idNO 등 최소 정보만 포함)
            String tempJwt = jwtTokenProvider.generateTemporaryToken(
                    provider.toUpperCase(),
                    memberResponse.getData().getMember().getIdNo()
            );

            // (2) Redis 등 임시 저장소에 OAuth2 유저 정보 저장 (TTL: 10~30분)
            redisService.saveOAuth2TempUser(tempJwt, memberResponse, 10 * 60);

            // (3) 에외 발생 및 임시 토큰 반환
            // 프론트엔드는 이 예외를 받아 회원가입 페이지로 리다이렉트, tempJwt를 쿼리스트링/헤더로 전달
            throw new OAuth2AdditionalSignupRequiredException(tempJwt);
        }

        // 5. 유저 정보가 있을 때: JWT 발급 및 반환
        CustomUserDetails userDetails = new CustomUserDetails(userResponse);

        String accessToken = jwtTokenProvider.generateToken(userDetails);
        String refreshToken = jwtTokenProvider.generateRefreshToken(userDetails);

        return new OAuth2LoginResponseDto(accessToken, refreshToken);
    }
}
