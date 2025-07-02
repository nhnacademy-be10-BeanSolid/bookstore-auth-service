package com.nhnacademy.authservice.domain.response;

import java.util.List;

public record TokenParseResponseDto(
        String username,
        List<String> authorities
) {
}
