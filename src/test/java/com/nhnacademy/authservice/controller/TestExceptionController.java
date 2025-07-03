package com.nhnacademy.authservice.controller;

import com.nhnacademy.authservice.exception.UserWithdrawnException;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;

@RestController
@RequestMapping("/test")
public class TestExceptionController {
    @GetMapping("/username-not-found")
    public void usernameNotFound() {
        throw new UsernameNotFoundException("사용자를 찾을 수 없습니다.");
    }

    @GetMapping("/feign-error")
    public void feignError() {
        throw new HttpClientErrorException(HttpStatus.BAD_REQUEST, "Feign 오류");
    }

    @GetMapping("/any-exception")
    public void anyException() {
        throw new RuntimeException("알 수 없는 오류");
    }

    @GetMapping("/user-withdrawn")
    public void userWithdrawn() { throw new UserWithdrawnException("탈퇴한 사용자입니다.");
    }
}
