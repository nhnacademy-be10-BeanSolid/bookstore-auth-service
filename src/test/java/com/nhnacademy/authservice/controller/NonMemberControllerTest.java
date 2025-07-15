package com.nhnacademy.authservice.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nhnacademy.authservice.dto.nonmember.request.NonMemberLoginRequest;
import com.nhnacademy.authservice.service.NonMemberService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(NonMemberController.class)
@AutoConfigureMockMvc(addFilters = false)
class NonMemberControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private NonMemberService nonMemberService;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @DisplayName("비회원 로그인 - 성공")
    void nonMemberLogin_Success() throws Exception {
        // given
        NonMemberLoginRequest request = new NonMemberLoginRequest("order123", "pass123");
        when(nonMemberService.validate(any(NonMemberLoginRequest.class))).thenReturn(true);

        // when & then
        mockMvc.perform(post("/auth/non-member/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").value(true));
    }

    @Test
    @DisplayName("비회원 로그인 - 실패 (자격 증명 불일치)")
    void nonMemberLogin_Fail_InvalidCredentials() throws Exception {
        // given
        NonMemberLoginRequest request = new NonMemberLoginRequest("order123", "wrong-pass");
        when(nonMemberService.validate(any(NonMemberLoginRequest.class))).thenReturn(false);

        // when & then
        mockMvc.perform(post("/auth/non-member/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").value(false));
    }

    
}
