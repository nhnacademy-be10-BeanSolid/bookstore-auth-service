package com.nhnacademy.authservice.dto.oauth2.request;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
public class OAuth2LoginRequestDto {
    @Schema(description = "OAuth2 제공자 (예: google, kakao, payco)", example = "payco")
    private String provider;
    @Schema(description = "OAuth2 제공자로부터 받은 인증 코드", example = "4/0AX4XfWj_...")
    private String code;
}