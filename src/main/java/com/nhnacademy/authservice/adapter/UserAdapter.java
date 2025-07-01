package com.nhnacademy.authservice.adapter;

import com.nhnacademy.authservice.domain.request.OAuth2UserCreateRequestDto;
import com.nhnacademy.authservice.domain.response.UserResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(name = "user-api")
public interface UserAdapter {
    @GetMapping("/users/{username}")
    UserResponse getUserByUsername(@PathVariable("username") String username);

    @PostMapping("/users/register/oauth2")
    UserResponse saveOAuth2User(@RequestBody OAuth2UserCreateRequestDto request);
}
