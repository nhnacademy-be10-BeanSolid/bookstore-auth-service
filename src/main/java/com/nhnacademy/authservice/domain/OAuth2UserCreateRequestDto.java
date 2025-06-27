package com.nhnacademy.authservice.domain;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class OAuth2UserCreateRequestDto {
    private String provider;
    private String providerId;
    private String userName;
    private String userPhoneNumber;
    private String userEmail;
    private String userMaskedEmail;
    private String userBirth;
}
