package com.nhnacademy.authservice.adapter;

import com.nhnacademy.authservice.domain.UserResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@FeignClient(name = "user-api", url = "http://localhost")
public interface UserAdapter {
    @GetMapping("/users/{username}")
    UserResponse getUserByUsername(@PathVariable("username") String username);
}
