package com.nhnacademy.authservice.advice;

import com.nhnacademy.authservice.controller.TestExceptionController;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = TestExceptionController.class)
@Import(GlobalExceptionHandler.class)
@AutoConfigureMockMvc(addFilters = false)
class GlobalExceptionHandlerTest {
    @Autowired
    private MockMvc mockMvc;

    @Test
    void handleUsernameNotFound() throws Exception {
        mockMvc.perform(get("/test/username-not-found"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.message").value("사용자를 찾을 수 없습니다."))
                .andExpect(jsonPath("$.time").exists());
    }

    @Test
    void handleUserWithdrawn() throws Exception {
        mockMvc.perform(get("/test/user-withdrawn")) // 이 경로는 UserWithdrawnException을 발생시키는 테스트 컨트롤러 엔드포인트입니다.
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403))
                .andExpect(jsonPath("$.message").value("탈퇴한 사용자입니다."))
                .andExpect(jsonPath("$.time").exists());
    }

    @Test
    void handleFeignError() throws Exception {
        mockMvc.perform(get("/test/feign-error"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.message").value("400 Feign 오류"))
                .andExpect(jsonPath("$.time").exists());
    }

    @Test
    void handleAll() throws Exception {
        mockMvc.perform(get("/test/any-exception"))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.status").value(500))
                .andExpect(jsonPath("$.message").value("서버 내부 오류가 발생했습니다."))
                .andExpect(jsonPath("$.time").exists());
    }
}