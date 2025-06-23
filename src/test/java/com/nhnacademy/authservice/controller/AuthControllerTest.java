package com.nhnacademy.authservice.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nhnacademy.authservice.domain.LoginRequestDto;
import com.nhnacademy.authservice.domain.LoginResponseDto;
import com.nhnacademy.authservice.domain.RefreshTokenResponseDto;
import com.nhnacademy.authservice.service.AuthService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


@WebMvcTest(AuthController.class)
@AutoConfigureMockMvc(addFilters = false)
class AuthControllerTest {
    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AuthService authService;

    @Autowired
    ObjectMapper objectMapper;

    @Test
    @DisplayName("로그인 성공")
    void login_success() throws Exception {
        // given
        LoginRequestDto loginRequest = new LoginRequestDto("testuser", "password");
        LoginResponseDto loginResponse = new LoginResponseDto("accessToken", "refreshToken");

        when(authService.login(eq("testuser"), eq("password")))
                .thenReturn(loginResponse);

        // when & then
        mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("accessToken"))
                .andExpect(jsonPath("$.refreshToken").value("refreshToken"));
    }

    @Test
    @DisplayName("리프레시 토큰 갱신 성공")
    void refreshToken_success() throws Exception {
        // given
        RefreshTokenResponseDto refreshResponse = new RefreshTokenResponseDto("new-access-token", "new-refresh-token");

        when(authService.refreshToken(anyString()))
                .thenReturn(refreshResponse);

        // when & then
        mockMvc.perform(post("/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString("refresh-token")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("new-access-token"))
                .andExpect(jsonPath("$.refreshToken").value("new-refresh-token"));
    }


}