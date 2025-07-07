package com.nhnacademy.authservice.service;

import com.nhnacademy.authservice.domain.request.OAuth2AdditionalSignupRequestDto;
import com.nhnacademy.authservice.domain.response.*;

public interface AuthService {
    LoginResponseDto login(String id, String password);

    RefreshTokenResponseDto refreshToken(String refreshToken);

    boolean validateToken(String token);

    TokenParseResponseDto parseToken(String token);

    ResponseDto<?> oauth2Login(String provider, String code);

    OAuth2LoginResponseDto completeOAuth2Signup(String tempJwt, OAuth2AdditionalSignupRequestDto additionalInfo);

    boolean verifyPassword(String userId, String password);
}
