package com.nhnacademy.authservice.exception;

public class VerificationCodeException extends RuntimeException {
    public VerificationCodeException(String message) {
        super(message);
    }
}
