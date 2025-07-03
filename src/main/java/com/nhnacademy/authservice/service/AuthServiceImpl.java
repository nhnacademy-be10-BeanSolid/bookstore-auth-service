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
import com.nhnacademy.authservice.userdetails.CustomUserDetails;
import com.nhnacademy.authservice.util.PhoneNumberUtils;
import feign.FeignException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

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
        userAdapter.updateLastLoginAt(id);
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
        UserResponse userResponse = null;
        try {
            userResponse = userAdapter.getUserByUsername(provider.toUpperCase() + memberResponse.getData().getMember().getIdNo());
        } catch (FeignException e) {
            if(e.status() != 404) {
                throw e;
            }
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
        if(userResponse.getUserStatus().equals("WITHDRAWN")) {
            throw new UserWithdrawnException(userResponse.getUserId() + "은(는) 탈퇴한 사용자입니다.");
        }

        // 5. 유저 정보가 있을 때: JWT 발급 및 반환
        CustomUserDetails userDetails = new CustomUserDetails(userResponse);

        String accessToken = jwtTokenProvider.generateToken(userDetails);
        String refreshToken = jwtTokenProvider.generateRefreshToken(userDetails);
        userAdapter.updateLastLoginAt(userResponse.getUserId());

        return ResponseDto.<OAuth2LoginResponseDto>builder()
                .success(true)
                .message("로그인 성공")
                .data(OAuth2LoginResponseDto.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .build())
                .build();
    }

    @Override
    public OAuth2LoginResponseDto completeOAuth2Signup(String tempJwt, OAuth2AdditionalSignupRequestDto additionalInfo) {
        // 1. 임시 토큰 파싱 및 검증
        Map<String, Object> claims = jwtTokenProvider.parseTemporaryToken(tempJwt);
        String provider = (String) claims.get("provider");
        String idNo = (String) claims.get("idNo");

        // 2. 회원 정보 생성 (임시 토큰 정보 + 추가 입력 정보)
        OAuth2UserCreateRequestDto createRequest = new OAuth2UserCreateRequestDto(
                provider,
                idNo,
                additionalInfo.getName(),
                additionalInfo.getMobile(),
                additionalInfo.getEmail(),
                additionalInfo.getBirth()
        );

        // 3. DB에 회원 저장
        UserResponse userResponse = userAdapter.saveOAuth2User(createRequest);

        // 4. JWT 토큰 발급
        CustomUserDetails userDetails = new CustomUserDetails(userResponse);
        String accessToken = jwtTokenProvider.generateToken(userDetails);
        String refreshToken = jwtTokenProvider.generateRefreshToken(userDetails);
        userAdapter.updateLastLoginAt(userResponse.getUserId());

        return new OAuth2LoginResponseDto(accessToken, refreshToken);
    }
}
