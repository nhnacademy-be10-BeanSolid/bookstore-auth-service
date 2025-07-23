package com.nhnacademy.authservice.advice;

import com.nhnacademy.authservice.exception.InvalidOAuth2ProviderException;
import com.nhnacademy.authservice.exception.InvalidTokenException;
import com.nhnacademy.authservice.exception.UserDormantException;
import com.nhnacademy.authservice.exception.UserWithdrawnException;
import com.nhnacademy.authservice.exception.VerificationCodeException;
import feign.FeignException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.client.HttpClientErrorException;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {
    // 인증 실패
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ErrorResponseDto> handleBadCredentials(BadCredentialsException ex) {
        log.error("BadCredentialsException: {}", ex.getMessage(), ex);
        ErrorResponseDto error = new ErrorResponseDto(
                HttpStatus.UNAUTHORIZED.value(),
                ex.getMessage(),
                LocalDateTime.now()
        );
        return new ResponseEntity<>(error, HttpStatus.UNAUTHORIZED);
    }

    // 탈퇴한 사용자 또는 휴면 사용자 로그인 (403 Forbidden)
    @ExceptionHandler({UserWithdrawnException.class, UserDormantException.class})
    public ResponseEntity<ErrorResponseDto> handleForbiddenExceptions(RuntimeException ex) {
        log.error("Forbidden Exception: {}", ex.getMessage(), ex);
        ErrorResponseDto error = new ErrorResponseDto(
                HttpStatus.FORBIDDEN.value(),
                ex.getMessage(),
                LocalDateTime.now()
        );
        return new ResponseEntity<>(error, HttpStatus.FORBIDDEN);
    }

    // 잘못된 요청 (400 Bad Request)
    @ExceptionHandler({
            VerificationCodeException.class,
            InvalidTokenException.class,
            InvalidOAuth2ProviderException.class
    })
    public ResponseEntity<ErrorResponseDto> handleBadRequestExceptions(RuntimeException ex) {
        log.error("Bad Request Exception: {}", ex.getMessage(), ex);
        ErrorResponseDto error = new ErrorResponseDto(
                HttpStatus.BAD_REQUEST.value(),
                ex.getMessage(),
                LocalDateTime.now()
        );
        return new ResponseEntity<>(error, HttpStatus.BAD_REQUEST);
    }

    // FeignClient 등 외부 API 호출 오류
    @ExceptionHandler(HttpClientErrorException.class)
    public ResponseEntity<ErrorResponseDto> handleFeignError(HttpClientErrorException ex) {
        log.error("HttpClientErrorException: {}", ex.getMessage(), ex);
        ErrorResponseDto error = new ErrorResponseDto(
                ex.getStatusCode().value(),
                ex.getMessage(),
                LocalDateTime.now()
        );
        return new ResponseEntity<>(error, ex.getStatusCode());
    }

    @ExceptionHandler(FeignException.class)
    public ResponseEntity<ErrorResponseDto> handleFeignException(FeignException ex) {
        log.error("FeignException: {}", ex.getMessage(), ex);
        ErrorResponseDto error = new ErrorResponseDto(
                ex.status(),
                ex.getMessage(),
                LocalDateTime.now()
        );
        return new ResponseEntity<>(error, HttpStatus.valueOf(ex.status()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponseDto> handleValidationExceptions(
            MethodArgumentNotValidException ex) {
        log.error("MethodArgumentNotValidException: {}", ex.getMessage(), ex);
        Map<String, String> fieldErrors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach(error -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            fieldErrors.put(fieldName, errorMessage);
        });

        ErrorResponseDto errorResponse = new ErrorResponseDto(
                HttpStatus.BAD_REQUEST.value(),
                "입력 값 유효성 검사에 실패했습니다.",
                LocalDateTime.now(),
                fieldErrors
        );

        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
    }

    // 기타 모든 예외
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponseDto> handleAll(Exception ex) {
        log.error("Unhandled Exception: {}", ex.getMessage(), ex);
        ErrorResponseDto error = new ErrorResponseDto(
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                "서버 내부 오류가 발생했습니다.",
                LocalDateTime.now()
        );
        return new ResponseEntity<>(error, HttpStatus.INTERNAL_SERVER_ERROR);
    }

}