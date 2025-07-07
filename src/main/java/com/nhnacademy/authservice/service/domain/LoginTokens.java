package com.nhnacademy.authservice.service.domain;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class LoginTokens {
    private String accessToken;
    private String refreshToken;
}
