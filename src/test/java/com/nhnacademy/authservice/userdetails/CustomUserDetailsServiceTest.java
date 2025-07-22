package com.nhnacademy.authservice.userdetails;

import com.nhnacademy.authservice.adapter.UserAdapter;
import com.nhnacademy.authservice.dto.user.response.UserResponse;
import feign.FeignException;
import feign.Request;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.nio.charset.StandardCharsets;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;
import static org.mockito.ArgumentMatchers.anyString;


@ExtendWith(MockitoExtension.class)
class CustomUserDetailsServiceTest {
    @Mock
    private UserAdapter userAdapter;

    @InjectMocks
    private CustomUserDetailsService customUserDetailsService;

    @Test
    @DisplayName("정상적으로 사용자 정보를 반환하는 경우")
    void loadUserByUsername_returnsUserDetails_whenUserExists() {
        UserResponse userResponse = new UserResponse();
        userResponse.setUserId("testuser");
        userResponse.setUserPassword("password");
        userResponse.setAuth(true);
        userResponse.setUserStatus("ACTIVE");

        when(userAdapter.getUserByUsername("testuser")).thenReturn(userResponse);

        UserDetails userDetails = customUserDetailsService.loadUserByUsername("testuser");

        assertNotNull(userDetails);
        assertEquals("testuser", userDetails.getUsername());
        assertEquals("password", userDetails.getPassword());
        assertTrue(userDetails.isEnabled());
    }

    @Test
    @DisplayName("사용자가 존재하지 않을 때 UsernameNotFoundException 발생")
    void loadUserByUsername_throwsException_whenUserNotFound() {
        // FeignException.NotFound 생성자를 올바르게 호출
        when(userAdapter.getUserByUsername(anyString())).thenThrow(
            new FeignException.NotFound(
                "User not found",
                Request.create(Request.HttpMethod.GET, "/users/unknown", Collections.emptyMap(), new byte[0], StandardCharsets.UTF_8),
                null,
                Collections.emptyMap()
            )
        );

        assertThrows(UsernameNotFoundException.class, () -> {
            customUserDetailsService.loadUserByUsername("unknown");
        });
    }
}
