package com.nhnacademy.authservice.service.impl;

import com.nhnacademy.authservice.adapter.UserAdapter;
import com.nhnacademy.authservice.dto.nonmember.request.NonMemberLoginRequest;
import com.nhnacademy.authservice.service.NonMemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class NonMemberServiceImpl implements NonMemberService {

    private final UserAdapter userAdapter;
    private final PasswordEncoder passwordEncoder;

    @Override
    public boolean validate(NonMemberLoginRequest request) {
        // orderId는 NonMemberLoginRequest에서 String으로 제공된다고 가정하고 Long으로 파싱합니다.
        // 이 부분은 나중에 orderAdapter를 통해 orderId를 얻는 로직으로 대체될 수 있습니다.
        Long orderId = Long.parseLong(request.getOrderId());
        String rawPassword = request.getPassword();

        String encryptedPassword = userAdapter.getGuestPassword(orderId);

        return passwordEncoder.matches(rawPassword, encryptedPassword);
    }
}
