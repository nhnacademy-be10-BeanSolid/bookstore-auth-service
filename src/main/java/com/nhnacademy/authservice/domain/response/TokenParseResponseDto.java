package com.nhnacademy.authservice.domain.response;

import com.nhnacademy.authservice.provider.UserType;

import java.util.List;

public record TokenParseResponseDto(
        String username,
        List<String> authorities,
        UserType userType
) {
}
