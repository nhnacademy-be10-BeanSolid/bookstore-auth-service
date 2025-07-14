package com.nhnacademy.authservice.controller;

import com.nhnacademy.authservice.dto.nonmember.request.NonMemberLoginRequest;
import com.nhnacademy.authservice.service.NonMemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class NonMemberController {

    private final NonMemberService nonMemberService;

    @PostMapping("/non-member/login")
    public ResponseEntity<Boolean> nonMemberLogin(@RequestBody NonMemberLoginRequest request) {
        boolean isValid = nonMemberService.validate(request);
        return ResponseEntity.ok(isValid);
    }
}
