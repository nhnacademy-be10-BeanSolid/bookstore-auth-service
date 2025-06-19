package com.nhnacademy.authservice.adapter;

import com.nhnacademy.bookstoreuserapi.domain.response.ResponseUser;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@FeignClient(name = "user-api")
public interface UserAdapter {
    @GetMapping("/users/{username}")
    ResponseUser getUserByUsername(@PathVariable("username") String username);
}
