package com.nhnacademy.authservice.service;

import com.nhnacademy.authservice.adapter.UserAdapter;
import com.nhnacademy.authservice.client.member.OAuth2MemberClient;
import com.nhnacademy.authservice.client.token.OAuth2TokenClient;
import com.nhnacademy.authservice.domain.request.OAuth2AdditionalSignupRequestDto;
import com.nhnacademy.authservice.domain.request.OAuth2UserCreateRequestDto;
import com.nhnacademy.authservice.domain.response.*;
import com.nhnacademy.authservice.exception.InvalidTokenException;
import com.nhnacademy.authservice.exception.UserWithdrawnException;
import com.nhnacademy.authservice.factory.OAuth2MemberClientFactory;
import com.nhnacademy.authservice.factory.OAuth2TokenClientFactory;
import com.nhnacademy.authservice.provider.JwtTokenProvider;
import com.nhnacademy.authservice.provider.UserType;
import com.nhnacademy.authservice.service.domain.LoginTokens;
import com.nhnacademy.authservice.userdetails.CustomUserDetails;
import com.nhnacademy.authservice.util.PhoneNumberUtils;
import feign.FeignException;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 인증 관련 비즈니스 로직을 처리하는 Service 구현체
 */
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final JwtTokenProvider jwtTokenProvider;
    private final OAuth2TokenClientFactory tokenClientFactory;
    private final OAuth2MemberClientFactory memberClientFactory;
    private final UserAdapter userAdapter;
    private final PasswordEncoder passwordEncoder;

    @Override
    public LoginResponseDto login(String id, String password) {
        UserDetails userDetails = (UserDetails) authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(id, password)).getPrincipal();
        LoginTokens tokens = issueTokens(userDetails, UserType.LOCAL);
        userAdapter.updateLastLoginAt(userDetails.getUsername());
        return new LoginResponseDto(tokens.getAccessToken(), tokens.getRefreshToken());
    }

    @Override
    public RefreshTokenResponseDto refreshToken(String refreshToken) {
        if(!jwtTokenProvider.validateToken(refreshToken)) {
            throw new InvalidTokenException("Invalid Refresh Token");
        }

        String username = jwtTokenProvider.getUsernameFromToken(refreshToken);
        UserDetails user = userDetailsService.loadUserByUsername(username);
        UserType userType = jwtTokenProvider.getUserTypeFromToken(refreshToken);
        LoginTokens tokens = issueTokens(user, userType);

        return new RefreshTokenResponseDto(tokens.getAccessToken(), tokens.getRefreshToken());
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
        UserType userType = jwtTokenProvider.getUserTypeFromToken(token);
        return new TokenParseResponseDto(username, authorities, userType);
    }

    @Override
    public ResponseDto<?> oauth2Login(String provider, String code) {
        // 1. 토큰 발급
        OAuth2TokenClient tokenClient = tokenClientFactory.getClient(provider.toLowerCase());
        OAuth2TokenResponse tokenResponse = tokenClient.getToken(code);

        // 2. accessToken 으로 사용자 정보 조회
        OAuth2MemberClient memberClient = memberClientFactory.getClient(provider.toLowerCase());
        OAuth2MemberResponse memberResponse = memberClient.getMember(tokenResponse.getAccess_token());

        String formattedMobile = PhoneNumberUtils.convertGlobalToKoreanPhoneNumber(
                memberResponse.getData().getMember().getMobile()
        );

        // 3. DB 에서 사용자 조회
        String usernameKey = provider.toUpperCase() + memberResponse.getData().getMember().getIdNo();
        UserResponse userResponse;
        try {
            userResponse = userAdapter.getUserByUsername(usernameKey);
        } catch (FeignException fe) {
            if(fe.status() != 404) {
                throw fe;
            }
            userResponse = null;
        }


        // 4. 유저 정보가 없을 때: 임시 JWT 발급
        if(userResponse == null) {
            String tempJwt = jwtTokenProvider.generateTemporaryToken(
                    provider.toUpperCase(),
                    memberResponse.getData().getMember().getIdNo()
            );

            return ResponseDto.<AdditionalSignupRequiredDto>builder()
                    .success(false)
                    .message("추가 회원가입이 필요합니다.")
                    .data(AdditionalSignupRequiredDto.builder()
                            .tempJwt(tempJwt)
                            .name(memberResponse.getData().getMember().getName())
                            .email(memberResponse.getData().getMember().getEmail())
                            .mobile(formattedMobile)
                            .build())
                    .build();
        }
        if("WITHDRAWN".equals(userResponse.getUserStatus())) {
            throw new UserWithdrawnException(userResponse.getUserId() + "은(는) 탈퇴한 사용자입니다.");
        }

        // 5. 유저 정보가 있을 때: JWT 발급 및 반환
        CustomUserDetails userDetails = new CustomUserDetails(userResponse);
        LoginTokens tokens = issueTokens(userDetails, UserType.OAUTH2);
        OAuth2LoginResponseDto resp = OAuth2LoginResponseDto.builder()
                .accessToken(tokens.getAccessToken())
                .refreshToken(tokens.getRefreshToken())
                .build();

        return ResponseDto.<OAuth2LoginResponseDto>builder()
                .success(true)
                .message("로그인 성공")
                .data(resp)
                .build();
    }

    @Override
    public OAuth2LoginResponseDto completeOAuth2Signup(String tempJwt, OAuth2AdditionalSignupRequestDto additionalInfo) {
        // 1. 임시 토큰 파싱 및 검증
        Claims claims = jwtTokenProvider.parseTemporaryToken(tempJwt);
        String provider = claims.get("provider", String.class);
        String idNo = claims.get("idNo", String.class);

        // 2. 회원 정보 생성 (임시 토큰 정보 + 추가 입력 정보)
        OAuth2UserCreateRequestDto createRequest = new OAuth2UserCreateRequestDto(
                provider, idNo,
                additionalInfo.getName(),
                additionalInfo.getMobile(),
                additionalInfo.getEmail(),
                additionalInfo.getBirth()
        );

        // 3. DB에 회원 저장
        UserResponse saved = userAdapter.saveOAuth2User(createRequest);

        // 4. JWT 토큰 발급
        CustomUserDetails userDetails = new CustomUserDetails(saved);
        LoginTokens tokens = issueTokens(userDetails, UserType.OAUTH2);

        return new OAuth2LoginResponseDto(tokens.getAccessToken(), tokens.getRefreshToken());
    }

    @Override
    public boolean verifyPassword(String userId, String password) {
        try {
            UserResponse userResponse = userAdapter.getUserByUsername(userId);

            if (userResponse == null) {
                return false;
            }

            return passwordEncoder.matches(password, userResponse.getUserPassword());
        } catch (FeignException fe) {
            if (fe.status() == 404) {
                return false;
            }
            throw fe;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 토큰 발급 공통 로직
     *
     * @param userDetails 사용자 상세 정보
     * @param userType 사용자 유형 (LOCAL/OAUTH2)
     * @return accessToken, refreshToken을 담은 DTO
     */
    private LoginTokens issueTokens(UserDetails userDetails, UserType userType) {
        String accessToken = jwtTokenProvider.generateAccessToken(userDetails, userType);
        String refreshToken = jwtTokenProvider.generateRefreshToken(userDetails, userType);
        return new LoginTokens(accessToken, refreshToken);
    }
}
