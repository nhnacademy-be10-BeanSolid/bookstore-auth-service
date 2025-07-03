package com.nhnacademy.authservice.exception;

public class UserWithdrawnException extends RuntimeException {
    public UserWithdrawnException(String message) {
        super(message);
    }
}
