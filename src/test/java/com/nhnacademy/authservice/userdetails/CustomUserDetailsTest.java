package com.nhnacademy.authservice.userdetails;

import com.nhnacademy.authservice.domain.UserResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Collection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CustomUserDetailsTest {
    private UserResponse createUser(boolean isAuth) {
        return new UserResponse(
                "testId",
                "testPassword",
                "홍길동",
                "010-1234-5678",
                "test@example.com",
                LocalDate.of(1990, 1, 1),
                100,
                isAuth,
                "ACTIVE",
                LocalDateTime.now(),
                "GOLD"
        );
    }

    @Test
    @DisplayName("isAuth가 true면 ROLE_ADMIN 반환")
    void getAuthorities_returnsAdminRole_whenUserIsAuth() {
        UserResponse user = createUser(true);
        CustomUserDetails userDetails = new CustomUserDetails(user);

        Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
        assertEquals(1, authorities.size());
        assertEquals("ROLE_ADMIN", authorities.iterator().next().getAuthority());
    }

    @Test
    @DisplayName("isAuth가 false면 ROLE_USER 반환")
    void getAuthorities_returnsUserRole_whenUserIsNotAuth() {
        UserResponse user = createUser(false);
        CustomUserDetails userDetails = new CustomUserDetails(user);

        Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
        assertEquals(1, authorities.size());
        assertEquals("ROLE_USER", authorities.iterator().next().getAuthority());
    }

    @Test
    @DisplayName("getUsername, getPassword가 UserResponse 값 반환")
    void getterMethods_returnUserResponseValues() {
        UserResponse user = createUser(true);
        CustomUserDetails userDetails = new CustomUserDetails(user);

        assertEquals("testId", userDetails.getUsername());
        assertEquals("testPassword", userDetails.getPassword());
    }

    @Test
    @DisplayName("계정 상태 관련 메서드는 true 반환")
    void accountStatusMethods_returnTrue() {
        UserResponse user = createUser(true);
        CustomUserDetails userDetails = new CustomUserDetails(user);

        assertTrue(userDetails.isAccountNonExpired());
        assertTrue(userDetails.isAccountNonLocked());
        assertTrue(userDetails.isCredentialsNonExpired());
        assertTrue(userDetails.isEnabled());
    }

}