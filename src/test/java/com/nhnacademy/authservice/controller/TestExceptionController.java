package com.nhnacademy.authservice.controller;

import com.nhnacademy.authservice.exception.UserDormantException;
import com.nhnacademy.authservice.exception.UserWithdrawnException;
import com.nhnacademy.authservice.exception.VerificationCodeException;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
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

    @GetMapping("/user-dormant")
    public void userDormant() { throw new UserDormantException("휴면 사용자입니다."); }

    @GetMapping("/verification-code")
    public void verificationCode() { throw new VerificationCodeException("인증 코드가 유효하지 않습니다."); }

    @PostMapping("/validation-error")
    public void validationError(@Valid @RequestBody TestDto testDto) {
        // This method will trigger MethodArgumentNotValidException if testDto is invalid
    }

    @Getter
    @NoArgsConstructor
    @AllArgsConstructor
    public static class TestDto {
        @NotBlank(message = "값은 비어 있을 수 없습니다.")
        private String value;
    }
}
