package com.nhnacademy.authservice.controller.api;

import com.nhnacademy.authservice.advice.ErrorResponseDto;
import com.nhnacademy.authservice.dto.nonmember.request.NonMemberLoginRequest;
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

@Tag(name = "비회원 API", description = "비회원 로그인 및 관련 기능 API")
@RequestMapping("/auth")
public interface NonMemberApi {

    @Operation(summary = "비회원 로그인", description = "주문 번호와 비밀번호를 사용하여 비회원 로그인 유효성을 검사합니다.",
        responses = {
            @ApiResponse(responseCode = "200", description = "비회원 로그인 유효성 검사 결과",
                content = @Content(mediaType = "application/json",
                    examples = {
                        @ExampleObject(
                            name = "비회원 로그인 성공 예시",
                            summary = "주문 번호와 비밀번호가 일치하는 경우",
                            value = "true"
                        ),
                        @ExampleObject(
                            name = "비회원 로그인 실패 예시",
                            summary = "주문 번호와 비밀번호가 일치하지 않는 경우",
                            value = "false"
                        )
                    }
                )
            ),
            @ApiResponse(responseCode = "400", description = "잘못된 요청",
                content = @Content(mediaType = "application/json",
                    schema = @Schema(implementation = ErrorResponseDto.class),
                    examples = @ExampleObject(
                        name = "유효성 검사 실패 예시",
                        summary = "필수 정보 누락 또는 형식 오류",
                        value = "{\"status\": 400, \"message\": \"입력 값 유효성 검사에 실패했습니다.\", \"timestamp\": \"2025-07-22T10:48:17.123\", \"fieldErrors\": {\"orderNumber\": \"주문 번호는 필수입니다.\"}}"
                    )
                )
            )
        }
    )
    @PostMapping("/non-member/login")
    ResponseEntity<Boolean> nonMemberLogin(
        @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "비회원 로그인 요청 정보 (주문 번호, 비밀번호)",
            required = true,
            content = @Content(
                mediaType = "application/json",
                examples = {
                    @ExampleObject(
                        name = "성공적인 비회원 로그인 요청",
                        summary = "유효한 주문 번호와 비밀번호",
                        value = "{\"orderNumber\": \"ORD123456789\", \"password\": \"nonmemberpass\"}"
                    )
                }
            )
        )
        @RequestBody NonMemberLoginRequest request);
}