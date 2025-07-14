package com.nhnacademy.authservice.dto.oauth2.response;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AdditionalSignupRequiredDto {
    private String tempJwt;
    private String name;
    private String email;
    private String mobile;
}
