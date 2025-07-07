package com.nhnacademy.authservice.provider;

/**
 * JWT 토큰에서 사요하는 사용자 유형을 정의하는 enum
 */
public enum UserType {
    LOCAL, // 일반 아이디/비밀번호 로그인
    OAUTH2 // OAuth2 로그인
}
