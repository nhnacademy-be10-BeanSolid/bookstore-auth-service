package com.nhnacademy.authservice.service;


import com.nhnacademy.authservice.dto.nonmember.request.NonMemberLoginRequest;

public interface NonMemberService {
    boolean validate(NonMemberLoginRequest request);
}