package com.nhnacademy.authservice.adapter;

import com.nhnacademy.authservice.domain.OAuth2MemberResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;

@FeignClient(name = "paycoMemberClient", url = "https://apis-payco.krp.toastoven.net")
public interface PaycoMemberAdapter {
    @PostMapping(value = "/payco/friends/find_member_v2.json", consumes = "application/json")
    OAuth2MemberResponse findMember(
            @RequestHeader("client_id") String clientId,
            @RequestHeader("access_token") String accessToken
    );
}
