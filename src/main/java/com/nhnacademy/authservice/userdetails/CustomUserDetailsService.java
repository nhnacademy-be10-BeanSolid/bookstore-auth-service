package com.nhnacademy.authservice.userdetails;

import com.nhnacademy.authservice.adapter.UserAdapter;
import com.nhnacademy.authservice.dto.user.response.UserResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import feign.FeignException;


@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserAdapter userAdapter;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserResponse userResponse;
        try {
            // User-API에 사용자 조회
            userResponse = userAdapter.getUserByUsername(username);
        } catch (FeignException.NotFound e) {
            throw new UsernameNotFoundException(username + "을(를) 찾을 수 없습니다.", e);
        } catch (FeignException e) {
            throw new UsernameNotFoundException("사용자 정보를 불러오는 중 오류가 발생했습니다: " + e.getMessage(), e);
        }


        if(userResponse == null) {
            throw new UsernameNotFoundException(username + "을(를) 찾을 수 없습니다.");
        }

        // UserDetails 구현체로 랩핑해 반환
        return new CustomUserDetails(userResponse);
    }
}
