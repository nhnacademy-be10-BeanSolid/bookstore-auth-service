package com.nhnacademy.authservice.dto.nonmember.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class NonMemberLoginRequest {
    private String orderNumber;
    private String password;
}
