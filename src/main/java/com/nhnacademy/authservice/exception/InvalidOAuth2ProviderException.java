package com.nhnacademy.authservice.exception;

public class InvalidOAuth2ProviderException extends RuntimeException {
    public InvalidOAuth2ProviderException(String provider) {
        super("지원하지 않는 OAuth2 제공자입니다: " + provider);
    }
}
