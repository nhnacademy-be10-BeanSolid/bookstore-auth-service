package com.nhnacademy.authservice.service;

import com.nhnacademy.authservice.dto.auth.response.LoginResponseDto;
import com.nhnacademy.authservice.dto.auth.response.RefreshTokenResponseDto;
import com.nhnacademy.authservice.dto.auth.response.TokenParseResponseDto;
import com.nhnacademy.authservice.dto.dormantuser.request.DormantUserVerificationRequestDto;
import com.nhnacademy.authservice.dto.oauth2.request.OAuth2AdditionalSignupRequestDto;
import com.nhnacademy.authservice.dto.oauth2.response.OAuth2LoginResponseDto;
import com.nhnacademy.authservice.dto.oauth2.response.ResponseDto;

public interface AuthService {
    LoginResponseDto login(String id, String password);

    RefreshTokenResponseDto refreshToken(String refreshToken);

    boolean validateToken(String token);

    TokenParseResponseDto parseToken(String token);

    ResponseDto<?> oauth2Login(String provider, String code);

    OAuth2LoginResponseDto completeOAuth2Signup(String tempJwt, OAuth2AdditionalSignupRequestDto additionalInfo);

    boolean verifyPassword(String userId, String password);

    boolean verifyDormantUserCode(DormantUserVerificationRequestDto dto);
}
