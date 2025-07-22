package com.nhnacademy.authservice.dto.nonmember.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class NonMemberLoginRequest {
    @NotBlank(message = "주문 번호는 비워둘 수 없습니다.")
    @Schema(description = "비회원 주문 번호", example = "ORD123456789")
    private String orderNumber;
    @NotBlank(message = "비밀번호는 비워둘 수 없습니다.")
    @Schema(description = "비회원 비밀번호", example = "nonmemberpass")
    private String password;
}