package com.nhnacademy.authservice.domain.request;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDate;

@Data
@Builder
public class OAuth2AdditionalSignupRequestDto {
    private String tempJwt;
    private String name;
    private String email;
    private String mobile;
    private LocalDate birth;
}
