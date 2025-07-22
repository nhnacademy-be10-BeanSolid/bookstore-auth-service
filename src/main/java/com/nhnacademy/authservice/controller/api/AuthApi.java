package com.nhnacademy.authservice.controller.api;

import com.nhnacademy.authservice.advice.ErrorResponseDto;
import com.nhnacademy.authservice.dto.auth.request.LoginRequestDto;
import com.nhnacademy.authservice.dto.auth.request.PasswordVerificationRequestDto;
import com.nhnacademy.authservice.dto.auth.response.RefreshTokenResponseDto;
import com.nhnacademy.authservice.dto.auth.response.TokenParseResponseDto;
import com.nhnacademy.authservice.dto.dormantuser.request.DormantUserVerificationRequestDto;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;

@Tag(name = "인증 API", description = "사용자 인증 및 권한 관련 API")
@RequestMapping("/auth")
public interface AuthApi {

    @Operation(summary = "사용자 로그인", description = "아이디와 비밀번호를 사용하여 로그인하고 JWT 토큰을 발급합니다.",
        responses = {
            @ApiResponse(responseCode = "200", description = "로그인 성공",
                content = @Content(mediaType = "application/json",
                    examples = @ExampleObject(
                        name = "로그인 성공 예시",
                        summary = "성공적인 로그인 응답",
                        value = "{\"accessToken\": \"eyJhbGciOiJIUzI1Ni...\", \"refreshToken\": \"eyJhbGciOiJIUzI1Ni...\"}"
                    )
                )
            ),
            @ApiResponse(responseCode = "401", description = "인증 실패",
                content = @Content(mediaType = "application/json",
                    schema = @Schema(implementation = ErrorResponseDto.class),
                    examples = @ExampleObject(
                        name = "인증 실패 예시",
                        summary = "잘못된 자격 증명",
                        value = "{\"status\": 401, \"message\": \"자격 증명에 실패하였습니다.\", \"time\": \"2025-07-22 10:48:17\"}"
                    )
                )
            ),
            @ApiResponse(responseCode = "403", description = "계정 상태 오류 (탈퇴 또는 휴면)",
                content = @Content(mediaType = "application/json",
                    schema = @Schema(implementation = ErrorResponseDto.class),
                    examples = {
                        @ExampleObject(
                            name = "탈퇴 사용자 예시",
                            summary = "탈퇴 상태의 사용자 로그인 시도",
                            value = "{\"status\": 403, \"message\": \"testuser은(는) 탈퇴한 사용자입니다.\", \"time\": \"2025-07-22 10:48:17\"}"
                        ),
                        @ExampleObject(
                            name = "휴면 사용자 예시",
                            summary = "휴면 상태의 사용자 로그인 시도",
                            value = "{\"status\": 403, \"message\": \"휴면 상태입니다. 두레이 메세지의 인증번호를 입력해주세요.\", \"time\": \"2025-07-22 10:48:17\"}"
                        )
                    }
                )
            )
        }
    )
    @PostMapping("/login")
    ResponseEntity<?> login(
        @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "로그인 요청 정보 (아이디, 비밀번호)",
            required = true,
            content = @Content(
                mediaType = "application/json",
                examples = {
                    @ExampleObject(
                        name = "일반 로그인 예시",
                        summary = "성공적인 로그인 요청",
                        value = "{\"id\": \"test\", \"password\": \"12345\"}"
                    ),
                    @ExampleObject(
                        name = "비밀번호 누락 예시",
                        summary = "비밀번호가 누락된 로그인 요청",
                        value = "{\"id\": \"test\", \"password\": \"\"}"
                    ),
                    @ExampleObject(
                        name = "탈퇴 사용자 로그인 예시",
                        summary = "탈퇴 상태의 사용자 로그인 요청",
                        value = "{\"id\": \"withdrawnUser\", \"password\": \"12345\"}"
                    ),
                    @ExampleObject(
                        name = "휴면 사용자 로그인 예시",
                        summary = "휴면 상태의 사용자 로그인 요청",
                        value = "{\"id\": \"dormantUser\", \"password\": \"12345\"}"
                    )
                }
            )
        )
        @RequestBody LoginRequestDto request);

    @Operation(summary = "비밀번호 확인", description = "사용자 ID와 비밀번호를 통해 비밀번호의 유효성을 검사합니다.",
        responses = {
            @ApiResponse(responseCode = "200", description = "비밀번호 확인 결과",
                content = @Content(mediaType = "application/json",
                    examples = {
                        @ExampleObject(
                            name = "비밀번호 일치 예시",
                            summary = "비밀번호가 일치하는 경우",
                            value = "true"
                        ),
                        @ExampleObject(
                            name = "비밀번호 불일치 예시",
                            summary = "비밀번호가 일치하지 않는 경우",
                            value = "false"
                        )
                    }
                )
            )
        }
    )
    @PostMapping("/verify-password")
    ResponseEntity<Boolean> verifyPassword(
            @Parameter(description = "사용자 ID", required = true, example = "test")
            @RequestHeader("X-USER-ID") String userId,
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                description = "비밀번호 확인 요청 정보",
                required = true,
                content = @Content(
                    mediaType = "application/json",
                    examples = {
                        @ExampleObject(
                            name = "비밀번호 확인 요청 성공 예시",
                            summary = "비밀번호 확인 요청",
                            value = "{\"password\": \"12345\"}"
                        ),
                        @ExampleObject(
                            name = "비밀번호 누락 예시",
                            summary = "비밀번호가 누락된 확인 요청",
                            value = "{\"password\": \"\"}"
                        )
                    }
                )
            )
            @RequestBody PasswordVerificationRequestDto request);

    @Operation(summary = "토큰 갱신", description = "만료된 JWT 토큰을 갱신합니다.",
        responses = {
            @ApiResponse(responseCode = "200", description = "토큰 갱신 성공",
                content = @Content(mediaType = "application/json",
                    examples = @ExampleObject(
                        name = "토큰 갱신 성공 예시",
                        summary = "성공적인 토큰 갱신 응답",
                        value = "{\"accessToken\": \"eyJhbGciOiJIUzI1Ni...\", \"refreshToken\": \"eyJhbGciOiJIUzI1Ni...\"}"
                    )
                )
            ),
            @ApiResponse(responseCode = "400", description = "유효하지 않은 토큰",
                content = @Content(mediaType = "application/json",
                    schema = @Schema(implementation = ErrorResponseDto.class),
                    examples = @ExampleObject(
                        name = "유효하지 않은 토큰 예시",
                        summary = "유효하지 않거나 만료된 리프레시 토큰",
                        value = "{\"status\": 400, \"message\": \"Invalid Refresh Token\", \"time\": \"2025-07-22 10:48:17\"}"
                    )
                )
            )
        }
    )
    @PostMapping("/refresh")
    ResponseEntity<RefreshTokenResponseDto> refreshToken(@io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "갱신할 리프레시 토큰",
            required = true,
            content = @Content(
                mediaType = "text/plain",
                examples = @ExampleObject(
                    name = "리프레시 토큰 예시",
                    summary = "리프레시 토큰 문자열",
                    value = "eyJhbGciOiJIUzI1Ni..."
                )
            )
        )
        @RequestBody String request);

    @Operation(summary = "토큰 유효성 검사", description = "주어진 토큰의 유효성을 검사합니다.",
        responses = {
            @ApiResponse(responseCode = "200", description = "토큰 유효성 검사 결과",
                content = @Content(mediaType = "application/json",
                    examples = {
                        @ExampleObject(
                            name = "토큰 유효성 검사 성공 예시",
                            summary = "유효한 토큰",
                            value = "true"
                        ),
                        @ExampleObject(
                            name = "토큰 유효성 검사 실패 예시",
                            summary = "유효하지 않거나 만료된 토큰",
                            value = "false"
                        )
                    }
                )
            )
        }
    )
    @PostMapping("/validate")
    ResponseEntity<Boolean> validateToken(@io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "유효성을 검사할 토큰",
            required = true,
            content = @Content(
                mediaType = "text/plain",
                examples = @ExampleObject(
                    name = "토큰 유효성 검사 예시",
                    summary = "토큰 문자열",
                    value = "eyJhbGciOiJIUzI1Ni..."
                )
            )
        )
        @RequestBody String token);

    @Operation(summary = "토큰 파싱", description = "주어진 토큰을 파싱하여 사용자 정보를 추출합니다.",
        responses = {
            @ApiResponse(responseCode = "200", description = "토큰 파싱 성공",
                content = @Content(mediaType = "application/json",
                    schema = @Schema(implementation = TokenParseResponseDto.class),
                    examples = @ExampleObject(
                        name = "토큰 파싱 성공 예시",
                        summary = "유효한 토큰 파싱 결과",
                        value = "{\"username\": \"test\", \"authorities\": [\"ROLE_USER\", \"ROLE_ADMIN\"], \"userType\": \"LOCAL\"}"
                    )
                )
            ),
            @ApiResponse(responseCode = "400", description = "유효하지 않은 토큰",
                content = @Content(mediaType = "application/json",
                    schema = @Schema(implementation = ErrorResponseDto.class),
                    examples = @ExampleObject(
                        name = "유효하지 않은 토큰 예시",
                        summary = "유효하지 않거나 만료된 토큰",
                        value = "{\"status\": 400, \"message\": \"Invalid Token\", \"time\": \"2025-07-22 10:48:17\"}"
                    )
                )
            )
        }
    )
    @PostMapping("/parse")
    ResponseEntity<TokenParseResponseDto> parseToken(@io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "파싱할 토큰",
            required = true,
            content = @Content(
                mediaType = "text/plain",
                examples = @ExampleObject(
                    name = "토큰 파싱 예시",
                    summary = "토큰 문자열",
                    value = "eyJhbGciOiJIUzI1Ni..."
                )
            )
        )
        @RequestBody String token);

    @Operation(summary = "휴면 사용자 인증 코드 확인", description = "휴면 사용자 인증 코드를 확인합니다.",
        responses = {
            @ApiResponse(responseCode = "200", description = "인증 코드 확인 결과",
                content = @Content(mediaType = "application/json",
                    examples = {
                        @ExampleObject(
                            name = "인증 코드 일치 예시",
                            summary = "인증 코드가 일치하는 경우",
                            value = "true"
                        ),
                        @ExampleObject(
                            name = "인증 코드 불일치 예시",
                            summary = "인증 코드가 일치하지 않는 경우",
                            value = "false"
                        )
                    }
                )
            ),
            @ApiResponse(responseCode = "400", description = "인증 코드 오류",
                content = @Content(mediaType = "application/json",
                    schema = @Schema(implementation = ErrorResponseDto.class),
                    examples = @ExampleObject(
                        name = "인증 코드 만료 또는 없음 예시",
                        summary = "인증 코드가 만료되었거나 존재하지 않는 경우",
                        value = "{\"status\": 400, \"message\": \"인증코드가 만료되었거나 존재하지 않습니다.\", \"time\": \"2025-07-22 10:48:17\"}"
                    )
                )
            )
        }
    )
    @PostMapping("/dormant/verify")
    ResponseEntity<Boolean> dormantVerify(@io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "휴면 사용자 인증 요청 정보",
            required = true,
            content = @Content(
                mediaType = "application/json",
                examples = @ExampleObject(
                    name = "휴면 사용자 인증 예시",
                    summary = "휴면 사용자 인증 요청",
                    value = "{\"userId\": \"dormantUser\", \"verificationCode\": \"123456\"}"
                )
            )
        )
        @RequestBody DormantUserVerificationRequestDto dto);
}