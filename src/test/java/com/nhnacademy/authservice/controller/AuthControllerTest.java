package com.nhnacademy.authservice.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nhnacademy.authservice.domain.request.LoginRequestDto;
import com.nhnacademy.authservice.domain.response.LoginResponseDto;
import com.nhnacademy.authservice.domain.response.RefreshTokenResponseDto;
import com.nhnacademy.authservice.domain.response.TokenParseResponseDto;
import com.nhnacademy.authservice.provider.UserType;
import com.nhnacademy.authservice.service.AuthService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.ArgumentMatchers.anyString;
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

        when(authService.login("testuser", "password"))
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

    @Test
    @DisplayName("토큰 유효성 검증 성공")
    void validateToken_success() throws Exception {
        // given
        when(authService.validateToken(anyString())).thenReturn(true);

        // when & then
        mockMvc.perform(post("/auth/validate")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString("test-token")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").value(true));
    }

    @Test
    @DisplayName("토큰 파싱 성공")
    void parseToken_success() throws Exception {
        // given
        List<String> authorities = List.of("ROLE_USER", "ROLE_ADMIN");
        TokenParseResponseDto parseResponse = new TokenParseResponseDto("testuser", authorities, UserType.LOCAL);
        when(authService.parseToken(anyString())).thenReturn(parseResponse);

        // when & then
        mockMvc.perform(post("/auth/parse")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString("test-token")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("testuser"))
                .andExpect(jsonPath("$.authorities[0]").value("ROLE_USER"))
                .andExpect(jsonPath("$.authorities[1]").value("ROLE_ADMIN"));
    }


}