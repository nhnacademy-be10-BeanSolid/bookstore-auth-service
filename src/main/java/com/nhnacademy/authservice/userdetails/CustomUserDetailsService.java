package com.nhnacademy.authservice.userdetails;

import com.nhnacademy.authservice.adapter.UserAdapter;
import com.nhnacademy.authservice.domain.UserResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    private final UserAdapter userAdapter;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // User-API에 사용자 조회
        UserResponse userResponse = userAdapter.getUserByUsername(username);
        if(userResponse == null) {
            throw new UsernameNotFoundException(username + "을(를) 찾을 수 없습니다.");
        }
        // UserDetails 구현체로 랩핑해 반환
        return new CustomUserDetails(userResponse);
    }
}
