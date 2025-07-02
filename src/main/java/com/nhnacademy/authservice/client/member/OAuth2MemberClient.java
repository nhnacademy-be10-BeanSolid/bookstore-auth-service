package com.nhnacademy.authservice.client.member;

import com.nhnacademy.authservice.domain.response.OAuth2MemberResponse;

public interface OAuth2MemberClient {
    OAuth2MemberResponse getMember(String accessToken);
}
