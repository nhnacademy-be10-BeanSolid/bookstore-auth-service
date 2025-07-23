package com.nhnacademy.authservice.advice;

import com.nhnacademy.authservice.controller.TestExceptionController;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = TestExceptionController.class)
@Import(GlobalExceptionHandler.class)
@AutoConfigureMockMvc(addFilters = false)
class GlobalExceptionHandlerTest {
    @Autowired
    private MockMvc mockMvc;

    @Test
    void handleBadCredentials() throws Exception {
        mockMvc.perform(get("/test/username-not-found"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.message").value("사용자를 찾을 수 없습니다."))
                .andExpect(jsonPath("$.time").exists());
    }

    @Test
    void handleForbiddenExceptions() throws Exception {
        // UserWithdrawnException 테스트
        mockMvc.perform(get("/test/user-withdrawn"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403))
                .andExpect(jsonPath("$.message").value("탈퇴한 사용자입니다."))
                .andExpect(jsonPath("$.time").exists());

        // UserDormantException 테스트
        mockMvc.perform(get("/test/user-dormant"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403))
                .andExpect(jsonPath("$.message").value("휴면 사용자입니다."))
                .andExpect(jsonPath("$.time").exists());
    }

    @Test
    void handleBadRequestExceptions() throws Exception {
        // VerificationCodeException 테스트
        mockMvc.perform(get("/test/verification-code"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.message").value("인증 코드가 유효하지 않습니다."))
                .andExpect(jsonPath("$.time").exists());

        // InvalidTokenException 테스트
        mockMvc.perform(get("/test/invalid-token"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.message").value("Invalid Token"))
                .andExpect(jsonPath("$.time").exists());

        // InvalidOAuth2ProviderException 테스트
        mockMvc.perform(get("/test/invalid-oauth2-provider"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.message").value("지원하지 않는 OAuth2 제공자입니다: unknown"))
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
    void handleValidationExceptions() throws Exception {
        mockMvc.perform(post("/test/validation-error")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}".getBytes())) // Empty content to trigger validation error
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.message").value("입력 값 유효성 검사에 실패했습니다."))
                .andExpect(jsonPath("$.errors.value").value("값은 비어 있을 수 없습니다."))
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
