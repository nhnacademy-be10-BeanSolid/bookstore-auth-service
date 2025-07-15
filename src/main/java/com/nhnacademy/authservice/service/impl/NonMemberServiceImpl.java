package com.nhnacademy.authservice.service.impl;

import com.nhnacademy.authservice.adapter.OrderAdapter;
import com.nhnacademy.authservice.adapter.UserAdapter;
import com.nhnacademy.authservice.dto.nonmember.request.NonMemberLoginRequest;
import com.nhnacademy.authservice.service.NonMemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class NonMemberServiceImpl implements NonMemberService {

    private final OrderAdapter orderAdapter;
    private final UserAdapter userAdapter;
    private final PasswordEncoder passwordEncoder;

    @Override
    public boolean validate(NonMemberLoginRequest request) {
        Long orderId = orderAdapter.getIdByOrderNumber(request.getOrderNumber());
        String rawPassword = request.getPassword();

        String encryptedPassword = userAdapter.getGuestPassword(orderId);

        return passwordEncoder.matches(rawPassword, encryptedPassword);
    }
}
