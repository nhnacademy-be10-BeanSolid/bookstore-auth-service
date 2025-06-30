package com.nhnacademy.authservice.service.auth;

import com.nhnacademy.authservice.domain.*;
import org.springframework.security.core.userdetails.UserDetails;

public interface AuthService {
    LoginResponseDto login(String id, String password);

    UserDetails authentication(String username, String password);

    RefreshTokenResponseDto refreshToken(String refreshToken);

    boolean validateToken(String token);

    TokenParseResponseDto parseToken(String token);

    ResponseDto<?> oauth2Login(String provider, String code);

    OAuth2LoginResponseDto completeOAuth2Signup(String tempJwt, OAuth2AdditionalSignupRequestDto additionalInfo);
}
