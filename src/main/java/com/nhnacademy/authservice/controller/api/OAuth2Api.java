package com.nhnacademy.authservice.controller.api;

import com.nhnacademy.authservice.advice.ErrorResponseDto;
import com.nhnacademy.authservice.dto.oauth2.request.OAuth2AdditionalSignupRequestDto;
import com.nhnacademy.authservice.dto.oauth2.request.OAuth2LoginRequestDto;
import com.nhnacademy.authservice.dto.oauth2.response.OAuth2LoginResponseDto;
import com.nhnacademy.authservice.dto.oauth2.response.ResponseDto;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

@Tag(name = "OAuth2 인증 API", description = "OAuth2를 통한 로그인 및 추가 회원가입 관련 API")
@RequestMapping("/oauth2")
public interface OAuth2Api {

    @Operation(summary = "OAuth2 로그인", description = "OAuth2 제공자로부터 받은 코드를 사용하여 로그인합니다.",
        responses = {
            @ApiResponse(responseCode = "200", description = "로그인 성공 또는 추가 회원가입 필요",
                content = @Content(mediaType = "application/json",
                    examples = {
                        @ExampleObject(
                            name = "로그인 성공 예시",
                            summary = "기존 사용자 로그인 성공",
                            value = "{\"success\": true, \"message\": \"로그인 성공\", \"data\": {\"accessToken\": \"eyJhbGciOiJIUzI1Ni...\", \"refreshToken\": \"eyJhbGciOiJIUzI1Ni...\"}}"
                        ),
                        @ExampleObject(
                            name = "추가 회원가입 필요 예시",
                            summary = "새로운 사용자, 추가 정보 입력 필요",
                            value = "{\"success\": false, \"message\": \"추가 회원가입이 필요합니다.\", \"data\": {\"tempJwt\": \"eyJhbGciOiJIUzI1Ni...\", \"name\": \"홍길동\", \"email\": \"hong@example.com\", \"mobile\": \"010-1234-5678\"}}"
                        )
                    }
                )
            ),
            @ApiResponse(responseCode = "400", description = "잘못된 요청",
                content = @Content(mediaType = "application/json",
                    schema = @Schema(implementation = ErrorResponseDto.class),
                    examples = @ExampleObject(
                        name = "지원하지 않는 제공자 예시",
                        summary = "지원하지 않는 OAuth2 제공자 요청",
                        value = "{\"status\": 400, \"message\": \"지원하지 않는 OAuth2 제공자입니다: invalid_provider\", \"time\": \"2025-07-22 10:48:17\"}"
                    )
                )
            ),
            @ApiResponse(responseCode = "403", description = "탈퇴 사용자",
                content = @Content(mediaType = "application/json",
                    schema = @Schema(implementation = ErrorResponseDto.class),
                    examples = @ExampleObject(
                        name = "탈퇴 사용자 예시",
                        summary = "탈퇴 상태의 사용자 로그인 시도",
                        value = "{\"status\": 403, \"message\": \"testuser은(는) 탈퇴한 사용자입니다.\", \"time\": \"2025-07-22 10:48:17\"}"
                    )
                )
            )
        }
    )
    @PostMapping("/login")
    ResponseEntity<ResponseDto<?>> oauth2Login(
        @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "OAuth2 로그인 요청 정보 (제공자, 인증 코드)",
            required = true,
            content = @Content(
                mediaType = "application/json",
                examples = {
                    @ExampleObject(
                        name = "페이코 로그인 예시",
                        summary = "페이코 OAuth2 로그인 요청",
                        value = "{\"provider\": \"payco\", \"code\": \"PAYCO_AUTH_CODE_HERE\"}"
                    )
                }
            )
        )
        @RequestBody OAuth2LoginRequestDto request);

    @Operation(summary = "OAuth2 추가 회원가입", description = "임시 토큰과 추가 정보를 사용하여 회원가입을 완료합니다.",
        responses = {
            @ApiResponse(responseCode = "200", description = "회원가입 완료 및 로그인 성공",
                content = @Content(mediaType = "application/json",
                    examples = @ExampleObject(
                        name = "회원가입 완료 예시",
                        summary = "회원가입 완료 및 로그인 성공",
                        value = "{\"accessToken\": \"eyJhbGciOiJIUzI1Ni...\", \"refreshToken\": \"eyJhbGciOiJIUzI1Ni...\"}"
                    )
                )
            )
        }
    )
    @PostMapping("/signup")
    ResponseEntity<OAuth2LoginResponseDto> additionalSignup(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                description = "추가 회원가입 요청 정보",
                required = true,
                content = @Content(
                    mediaType = "application/json",
                    examples = {
                        @ExampleObject(
                            name = "성공적인 추가 회원가입 요청",
                            summary = "모든 필수 정보가 포함된 요청",
                            value = "{\"tempJwt\": \"valid_temp_jwt\", \"name\": \"홍길동\", \"email\": \"hong@example.com\", \"mobile\": \"010-1234-5678\", \"birth\": \"1990-01-01\"}"
                        ),
                        @ExampleObject(
                            name = "이름 누락 요청",
                            summary = "이름 필드가 누락된 요청",
                            value = "{\"tempJwt\": \"valid_temp_jwt\", \"email\": \"hong@example.com\", \"mobile\": \"010-1234-5678\", \"birth\": \"1990-01-01\"}"
                        )
                    }
                )
            )
            @RequestBody OAuth2AdditionalSignupRequestDto request);
}