package com.nhnacademy.authservice.domain;

import lombok.Data;

import java.time.LocalDate;

@Data
public class OAuth2AdditionalSignupRequestDto {
    private String tempJwt;
    private String name;
    private String email;
    private String mobile;
    private LocalDate birth;
}
