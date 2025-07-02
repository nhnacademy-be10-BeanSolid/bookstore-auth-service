package com.nhnacademy.authservice.domain.request;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.time.LocalDate;

@Data
@AllArgsConstructor
public class OAuth2UserCreateRequestDto {
    private String provider;
    private String providerId;
    private String userName;
    private String userPhoneNumber;
    private String userEmail;
    private LocalDate userBirth;
}
