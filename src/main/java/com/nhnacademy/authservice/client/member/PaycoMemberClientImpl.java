package com.nhnacademy.authservice.client.member;

import com.nhnacademy.authservice.adapter.PaycoMemberClient;
import com.nhnacademy.authservice.domain.OAuth2MemberResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component("paycoMemberClient")
@RequiredArgsConstructor
public class PaycoMemberClientImpl implements OAuth2MemberClient {
    private final PaycoMemberClient paycoMemberClient;

    @Value("${payco.client-id}")
    private String clientId;

    @Override
    public OAuth2MemberResponse getMember(String accessToken) {
        return paycoMemberClient.findMember(clientId, accessToken);
    }
}
