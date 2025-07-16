package com.nhnacademy.authservice.exception;

public class UserDormantException extends RuntimeException {
    public UserDormantException(String message) {
        super(message);
    }
}
