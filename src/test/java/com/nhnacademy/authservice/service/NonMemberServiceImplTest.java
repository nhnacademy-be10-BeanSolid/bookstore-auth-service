package com.nhnacademy.authservice.service;

import com.nhnacademy.authservice.adapter.OrderAdapter;
import com.nhnacademy.authservice.adapter.UserAdapter;
import com.nhnacademy.authservice.dto.nonmember.request.NonMemberLoginRequest;
import com.nhnacademy.authservice.service.impl.NonMemberServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class NonMemberServiceImplTest {

    @Mock
    private OrderAdapter orderAdapter;

    @Mock
    private UserAdapter userAdapter;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private NonMemberServiceImpl nonMemberService;

    private NonMemberLoginRequest loginRequest;

    @BeforeEach
    void setUp() {
        loginRequest = new NonMemberLoginRequest("orderNumber123", "password123");
    }

    @Test
    @DisplayName("비회원 로그인 성공")
    void validate_Success() {
        // given
        Long orderId = 1L;
        String encryptedPassword = "encryptedPassword";
        when(orderAdapter.getIdByOrderNumber(anyString())).thenReturn(orderId);
        when(userAdapter.getGuestPassword(anyLong())).thenReturn(encryptedPassword);
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(true);

        // when
        boolean result = nonMemberService.validate(loginRequest);

        // then
        assertThat(result).isTrue();
    }

    @Test
    @DisplayName("실패: 존재하지 않는 주문번호")
    void validate_Fail_OrderNotFound() {
        // given
        when(orderAdapter.getIdByOrderNumber(anyString())).thenReturn(null);

        // when
        boolean result = nonMemberService.validate(loginRequest);

        // then
        assertThat(result).isFalse();
    }

    @Test
    @DisplayName("실패: 주문에 해당하는 비밀번호 없음")
    void validate_Fail_PasswordNotFound() {
        // given
        Long orderId = 1L;
        when(orderAdapter.getIdByOrderNumber(anyString())).thenReturn(orderId);
        when(userAdapter.getGuestPassword(anyLong())).thenReturn(null);

        // when
        boolean result = nonMemberService.validate(loginRequest);

        // then
        assertThat(result).isFalse();
    }
    
    @Test
    @DisplayName("실패: 주문에 해당하는 비밀번호가 비어있음")
    void validate_Fail_PasswordIsEmpty() {
        // given
        Long orderId = 1L;
        when(orderAdapter.getIdByOrderNumber(anyString())).thenReturn(orderId);
        when(userAdapter.getGuestPassword(anyLong())).thenReturn("");

        // when
        boolean result = nonMemberService.validate(loginRequest);

        // then
        assertThat(result).isFalse();
    }

    @Test
    @DisplayName("실패: 비밀번호 불일치")
    void validate_Fail_PasswordMismatch() {
        // given
        Long orderId = 1L;
        String encryptedPassword = "encryptedPassword";
        when(orderAdapter.getIdByOrderNumber(anyString())).thenReturn(orderId);
        when(userAdapter.getGuestPassword(anyLong())).thenReturn(encryptedPassword);
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(false);

        // when
        boolean result = nonMemberService.validate(loginRequest);

        // then
        assertThat(result).isFalse();
    }
}
