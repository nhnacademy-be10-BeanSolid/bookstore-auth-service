package com.nhnacademy.authservice.dto.oauth2.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.*;
import lombok.Builder;
import lombok.Data;
import java.time.LocalDate;

@Data
@Builder
public class OAuth2AdditionalSignupRequestDto {
    @NotBlank(message = "임시 토큰은 필수입니다.")
    @Schema(description = "OAuth2 임시 JWT 토큰", example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
    private String tempJwt;
    @NotBlank(message = "이름은 필수입니다.")
    @Size(max = 20, message = "이름은 20자 이하여야 합니다.")
    @Schema(description = "사용자 이름", example = "홍길동")
    private String name;
    @NotBlank(message = "이메일은 필수입니다.")
    @Email(message = "유효한 이메일 형식이 아닙니다.")
    @Size(max = 50, message = "이메일은 50자 이하여야 합니다.")
    @Schema(description = "사용자 이메일", example = "hong.gildong@example.com")
    private String email;
    @NotBlank(message = "휴대폰 번호는 필수입니다.")
    @Pattern(regexp = "^01[016-9]-(?:\\d{3}|\\d{4})-\\d{4}$", message = "유효한 휴대폰 번호 형식이 아닙니다.")
    @Size(max = 15, message = "연락처는 15자 이하여야 합니다.")
    @Schema(description = "사용자 휴대폰 번호", example = "010-1234-5678")
    private String mobile;
    @NotNull(message = "생일은 필수입니다.")
    @PastOrPresent(message = "생일은 미래 날짜일 수 없습니다.")
    @Schema(description = "사용자 생년월일", example = "1990-01-01")
    private LocalDate birth;
}
