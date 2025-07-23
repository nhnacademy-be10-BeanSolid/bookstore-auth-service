package com.nhnacademy.authservice.service;

import com.nhnacademy.authservice.adapter.DoorayAdapter;
import com.nhnacademy.authservice.adapter.UserAdapter;
import com.nhnacademy.authservice.client.dooray.MessagePayload;
import com.nhnacademy.authservice.client.member.OAuth2MemberClient;
import com.nhnacademy.authservice.client.token.OAuth2TokenClient;
import com.nhnacademy.authservice.dto.auth.response.LoginResponseDto;
import com.nhnacademy.authservice.dto.auth.response.RefreshTokenResponseDto;
import com.nhnacademy.authservice.dto.auth.response.TokenParseResponseDto;
import com.nhnacademy.authservice.dto.dormantuser.request.DormantUserVerificationRequestDto;
import com.nhnacademy.authservice.dto.oauth2.request.OAuth2AdditionalSignupRequestDto;
import com.nhnacademy.authservice.dto.oauth2.request.OAuth2UserCreateRequestDto;
import com.nhnacademy.authservice.dto.oauth2.response.*;
import com.nhnacademy.authservice.dto.user.response.UserResponse;
import com.nhnacademy.authservice.exception.InvalidTokenException;
import com.nhnacademy.authservice.exception.UserDormantException;
import com.nhnacademy.authservice.exception.UserWithdrawnException;
import com.nhnacademy.authservice.exception.VerificationCodeException;
import com.nhnacademy.authservice.factory.OAuth2MemberClientFactory;
import com.nhnacademy.authservice.factory.OAuth2TokenClientFactory;
import com.nhnacademy.authservice.provider.JwtTokenProvider;
import com.nhnacademy.authservice.provider.UserType;
import com.nhnacademy.authservice.service.impl.AuthServiceImpl;
import com.nhnacademy.authservice.userdetails.CustomUserDetails;
import feign.FeignException;
import feign.Request;
import feign.Response;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.LocalDate;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
@ExtendWith(MockitoExtension.class)
@DisplayName("Auth 서비스 테스트")
class AuthServiceImplTest {
    @Mock private AuthenticationManager authenticationManager;
    @Mock private UserDetailsService userDetailsService;
    @Mock private JwtTokenProvider jwtTokenProvider;
    @Mock private OAuth2TokenClientFactory tokenClientFactory;
    @Mock private OAuth2MemberClientFactory memberClientFactory;
    @Mock private OAuth2TokenClient tokenClient;
    @Mock private OAuth2MemberClient memberClient;
    @Mock UserAdapter userAdapter;
    @Mock DoorayAdapter doorayAdapter;
    @Mock UserDetails userDetails;
    @Mock Authentication authentication;
    @Mock PasswordEncoder passwordEncoder;
    @InjectMocks
    AuthServiceImpl authService;
    @Mock RedisTemplate<String, String> redisTemplate;
    @Mock ValueOperations<String, String> valueOperations;

    @Test
    @DisplayName("로그인 성공")
    void login_success() {
        // given
        String id = "user";
        String pw = "pw";
        String accessToken = "access-token";
        String refreshToken = "refresh-token";

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(userDetails);
        when(userDetails.getUsername()).thenReturn(id);
        when(jwtTokenProvider.generateAccessToken(userDetails, UserType.LOCAL)).thenReturn(accessToken);
        when(jwtTokenProvider.generateRefreshToken(userDetails, UserType.LOCAL)).thenReturn(refreshToken);

        UserResponse activeUserResponse = mock(UserResponse.class);
        when(userAdapter.getUserByUsername(id)).thenReturn(activeUserResponse);
        when(activeUserResponse.getUserStatus()).thenReturn("ACTIVE");

        LoginResponseDto result = authService.login(id, pw);

        assertEquals(accessToken, result.accessToken());
        assertEquals(refreshToken, result.refreshToken());
        verify(userAdapter).updateLastLoginAt(id);
    }

    @Test
    @DisplayName("탈퇴한 사용자로 로그인 시 예외 발생")
    void login_withdrawnUser_throwsUserWithdrawnException() {
        String id = "withdrawnUser";
        String pw = "pw";

        UserResponse withdrawnUserResponse = mock(UserResponse.class);
        when(authenticationManager.authenticate(any())).thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(userDetails);
        when(userDetails.getUsername()).thenReturn(id);
        when(userAdapter.getUserByUsername(id)).thenReturn(withdrawnUserResponse);
        when(withdrawnUserResponse.getUserStatus()).thenReturn("WITHDRAWN");
        when(withdrawnUserResponse.getUserId()).thenReturn(id);

        assertThrows(UserWithdrawnException.class, () -> authService.login(id, pw));
    }

    @Test
    @DisplayName("리프레시 토큰으로 재발급 성공")
    void refreshToken_success() {
        String refreshToken = "refresh-token";
        String username = "user";
        UserType userType = UserType.LOCAL;
        String newAccessToken = "new-access";
        String newRefreshToken = "new-refresh";

        when(jwtTokenProvider.validateToken(refreshToken)).thenReturn(true);
        when(jwtTokenProvider.getUsernameFromToken(refreshToken)).thenReturn(username);
        when(jwtTokenProvider.getUserTypeFromToken(refreshToken)).thenReturn(userType);
        when(userDetailsService.loadUserByUsername(username)).thenReturn(userDetails);
        when(jwtTokenProvider.generateAccessToken(userDetails, userType)).thenReturn(newAccessToken);
        when(jwtTokenProvider.generateRefreshToken(userDetails, userType)).thenReturn(newRefreshToken);

        RefreshTokenResponseDto result = authService.refreshToken(refreshToken);

        assertEquals(newAccessToken, result.accessToken());
        assertEquals(newRefreshToken, result.refreshToken());
    }

    @Test
    @DisplayName("유효하지 않은 리프레시 토큰으로 재발급 시 예외 발생")
    void refreshToken_invalidToken_throwsException() {
        String refreshToken = "invalid";
        when(jwtTokenProvider.validateToken(refreshToken)).thenReturn(false);

        assertThrows(InvalidTokenException.class, () ->
                authService.refreshToken(refreshToken));
    }

    @Test
    @DisplayName("토큰 유효성 검사 성공")
    void validateToken_success() {
        String token = "token";
        when(jwtTokenProvider.validateToken(token)).thenReturn(true);

        assertTrue(authService.validateToken(token));
    }

    @Test
    @DisplayName("토큰 파싱 성공")
    void parseToken_success() {
        String token = "valid-token";
        String username = "testuser";
        List<String> authorities = List.of("ROLE_USER", "ROLE_ADMIN");

        when(jwtTokenProvider.validateToken(token)).thenReturn(true);
        when(jwtTokenProvider.getUsernameFromToken(token)).thenReturn(username);
        when(jwtTokenProvider.getAuthoritiesFromToken(token)).thenReturn(authorities);

        TokenParseResponseDto result = authService.parseToken(token);

        assertEquals(username, result.username());
        assertEquals(authorities, result.authorities());
    }

    @Test
    @DisplayName("유효하지 않은 토큰 파싱 시 예외 발생")
    void parseToken_invalidToken_throwsException() {
        String token = "invalid-token";
        when(jwtTokenProvider.validateToken(token)).thenReturn(false);

        assertThrows(InvalidTokenException.class, () -> authService.parseToken(token));
    }

    @Test
    @DisplayName("OAuth2 신규 사용자 로그인 시 추가 정보 입력 필요")
    void oauth2Login_newUser_returnsAdditionalSignupRequired() {
        String provider = "payco";
        String code = "auth_code";
        String accessToken = "oauth_access_token";
        String idNo = "user123";
        String mobile = "821012345678";
        String formattedMobile = "010-1234-5678";
        String tempJwt = "temp_jwt";

        OAuth2TokenResponse tokenResponse = OAuth2TokenResponse.builder().access_token(accessToken).build();

        OAuth2MemberResponse memberResponse = new OAuth2MemberResponse();
        OAuth2MemberResponse.Data data = new OAuth2MemberResponse.Data();
        OAuth2MemberResponse.Member member = new OAuth2MemberResponse.Member();
        member.setIdNo(idNo);
        member.setName("Name");
        member.setEmail("email@test.com");
        member.setMobile(mobile);
        data.setMember(member);
        memberResponse.setData(data);

        when(tokenClientFactory.getClient(provider)).thenReturn(tokenClient);
        when(tokenClient.getToken(code)).thenReturn(tokenResponse);

        when(memberClientFactory.getClient(provider)).thenReturn(memberClient);
        when(memberClient.getMember(accessToken)).thenReturn(memberResponse);

        when(userAdapter.getUserByUsername(anyString())).thenThrow(new FeignException.NotFound("", mock(), null, null));

        when(jwtTokenProvider.generateTemporaryToken(provider.toUpperCase(), idNo)).thenReturn(tempJwt);

        ResponseDto<?> response = authService.oauth2Login(provider, code);

        assertFalse(response.isSuccess());
        assertEquals("추가 회원가입이 필요합니다.", response.getMessage());

        AdditionalSignupRequiredDto dataResponse = (AdditionalSignupRequiredDto) response.getData();
        assertEquals(tempJwt, dataResponse.getTempJwt());
        assertEquals("Name", dataResponse.getName());
        assertEquals("email@test.com", dataResponse.getEmail());
        assertEquals(formattedMobile, dataResponse.getMobile());
    }

    @Test
    @DisplayName("OAuth2 기존 사용자 로그인 성공")
    void oauth2Login_existingUser_returnsTokens() {
        String provider = "payco";
        String code = "auth_code";
        String accessToken = "oauth_access_token";
        String idNo = "user123";
        String mobile = "821012345678";
        UserResponse userResponse = new UserResponse();
        userResponse.setUserStatus("ACTIVE");

        OAuth2TokenResponse tokenResponse = OAuth2TokenResponse.builder().access_token(accessToken).build();

        OAuth2MemberResponse memberResponse = new OAuth2MemberResponse();
        OAuth2MemberResponse.Data data = new OAuth2MemberResponse.Data();
        OAuth2MemberResponse.Member member = new OAuth2MemberResponse.Member();
        member.setIdNo(idNo);
        member.setName("Name");
        member.setEmail("email@test.com");
        member.setMobile(mobile);
        data.setMember(member);
        memberResponse.setData(data);

        when(tokenClientFactory.getClient(provider)).thenReturn(tokenClient);
        when(tokenClient.getToken(code)).thenReturn(tokenResponse);

        when(memberClientFactory.getClient(provider)).thenReturn(memberClient);
        when(memberClient.getMember(accessToken)).thenReturn(memberResponse);

        when(userAdapter.getUserByUsername(anyString())).thenReturn(userResponse);

        when(jwtTokenProvider.generateAccessToken(any(CustomUserDetails.class), any())).thenReturn("access-token");
        when(jwtTokenProvider.generateRefreshToken(any(CustomUserDetails.class), any())).thenReturn("refresh-token");

        ResponseDto<?> response = authService.oauth2Login(provider, code);

        assertTrue(response.isSuccess());
        OAuth2LoginResponseDto loginResponseDto = (OAuth2LoginResponseDto) response.getData();
        assertEquals("access-token", loginResponseDto.getAccessToken());
        assertEquals("refresh-token", loginResponseDto.getRefreshToken());

    }

    @Test
    @DisplayName("OAuth2 탈퇴한 사용자 로그인 시 예외 발생")
    void oauth2Login_withdrawnUser_throwsUserWithdrawnException() {
        String provider = "payco";
        String code = "auth_code";
        String accessToken = "oauth_access_token";
        String idNo = "user123";
        String mobile = "821012345678";

        OAuth2TokenResponse tokenResponse = OAuth2TokenResponse.builder().access_token(accessToken).build();

        OAuth2MemberResponse memberResponse = new OAuth2MemberResponse();
        OAuth2MemberResponse.Data data = new OAuth2MemberResponse.Data();
        OAuth2MemberResponse.Member member = new OAuth2MemberResponse.Member();
        member.setIdNo(idNo);
        member.setName("Name");
        member.setEmail("email@test.com");
        member.setMobile(mobile);
        data.setMember(member);
        memberResponse.setData(data);

        UserResponse withdrawnUser = new UserResponse();
        withdrawnUser.setUserId(provider.toUpperCase() + idNo);
        withdrawnUser.setUserStatus("WITHDRAWN");

        when(tokenClientFactory.getClient(provider)).thenReturn(tokenClient);
        when(tokenClient.getToken(code)).thenReturn(tokenResponse);
        when(memberClientFactory.getClient(provider)).thenReturn(memberClient);
        when(memberClient.getMember(accessToken)).thenReturn(memberResponse);
        when(userAdapter.getUserByUsername(anyString())).thenReturn(withdrawnUser);

        assertThrows(UserWithdrawnException.class, () -> {
            authService.oauth2Login(provider, code);
        });
    }

    @Test
    @DisplayName("OAuth2 추가 회원가입 완료 성공")
    void completeOAuth2Signup_success_returnsTokens() {
        String tempJwt = "temp_jwt";
        OAuth2AdditionalSignupRequestDto additionalInfo = OAuth2AdditionalSignupRequestDto.builder()
                .name("Name")
                .mobile("010-1234-5678")
                .email("email@test.com")
                .birth(LocalDate.parse("1990-01-01"))
                .build();
        UserResponse savedUser = new UserResponse();
        savedUser.setUserId("PAYCOuser123");
        savedUser.setUserStatus("ACTIVE");

        Claims claims = Mockito.mock(Claims.class);
        when(claims.get("provider", String.class)).thenReturn("PAYCO");
        when(claims.get("idNo", String.class)).thenReturn("user123");

        when(jwtTokenProvider.parseTemporaryToken(tempJwt)).thenReturn(claims);
        when(userAdapter.saveOAuth2User(any(OAuth2UserCreateRequestDto.class))).thenReturn(savedUser);

        when(jwtTokenProvider.generateAccessToken(any(CustomUserDetails.class), eq(UserType.OAUTH2))).thenReturn("access-token");
        when(jwtTokenProvider.generateRefreshToken(any(CustomUserDetails.class), any())).thenReturn("refresh-token");

        OAuth2LoginResponseDto response = authService.completeOAuth2Signup(tempJwt, additionalInfo);

        assertEquals("access-token", response.getAccessToken());
        assertEquals("refresh-token", response.getRefreshToken());

        ArgumentCaptor<OAuth2UserCreateRequestDto> captor = ArgumentCaptor.forClass(OAuth2UserCreateRequestDto.class);
        verify(userAdapter).saveOAuth2User(captor.capture());

        OAuth2UserCreateRequestDto dto = captor.getValue();
        assertEquals("PAYCO", dto.getProvider());
        assertEquals("user123", dto.getProviderId());
        assertEquals("Name", dto.getUserName());
        assertEquals("010-1234-5678", dto.getUserPhoneNumber());
        assertEquals("email@test.com", dto.getUserEmail());
        assertEquals(LocalDate.parse("1990-01-01"), dto.getUserBirth());
    }

    @Test
    @DisplayName("유효하지 않은 임시 JWT로 추가 회원가입 시 예외 발생")
    void completeOAuth2Signup_invalidTempJwt_throwsInvalidTokenException() {
        String tempJwt = "invalid_temp_jwt";
        OAuth2AdditionalSignupRequestDto additionalInfo = OAuth2AdditionalSignupRequestDto.builder().build(); // 최소한의 DTO

        when(jwtTokenProvider.parseTemporaryToken(tempJwt)).thenThrow(new JwtException("Expired JWT"));

        assertThrows(InvalidTokenException.class, () -> authService.completeOAuth2Signup(tempJwt, additionalInfo));
    }

    @Test
    @DisplayName("비밀번호 검증 성공")
    void verifyPassword_validUser_returnsTrue() {
        String userId = "user123";
        String rawPw = "pw";
        UserResponse userResponse = new UserResponse();
        userResponse.setUserStatus("ACTIVE");
        userResponse.setUserPassword("encrypted");
        when(userAdapter.getUserByUsername(userId)).thenReturn(userResponse);
        when(passwordEncoder.matches(rawPw, "encrypted")).thenReturn(true);

        boolean result = authService.verifyPassword(userId, rawPw);

        assertTrue(result);
    }

    @Test
    @DisplayName("사용자 응답이 null일 때 비밀번호 검증 실패")
    void verifyPassword_userResponseNull_returnsFalse() {
        String userId = "user123";
        String pw = "pw";

        when(userAdapter.getUserByUsername(userId)).thenReturn(null);

        boolean result = authService.verifyPassword(userId, pw);

        assertFalse(result);
    }

    @Test
    @DisplayName("Feign 오류(404 제외) 발생 시 비밀번호 검증 실패")
    void verifyPassword_feignErrorNon404_throwsFeignException() {
        String userId = "user123";
        String pw = "pw";
        FeignException fe = FeignException.errorStatus("error", Response.builder()
                .status(500)
                .request(Request.create(Request.HttpMethod.GET, "/", Collections.emptyMap(), new byte[0], StandardCharsets.UTF_8))
                .build());

        when(userAdapter.getUserByUsername(userId)).thenThrow(fe);

        assertThrows(FeignException.class, () ->
                authService.verifyPassword(userId, pw));
    }

    @Test
    @DisplayName("휴면 사용자로 로그인 시 인증 코드 전송 및 예외 발생")
    void login_dormantUser_sendsCodeToRedisAndDoorayAndThrows() {
        String id = "dormantUser";
        String pw = "pw";

        UserResponse dormantUser = mock(UserResponse.class);
        when(authenticationManager.authenticate(any())).thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(userDetails);
        when(userDetails.getUsername()).thenReturn(id);
        when(userAdapter.getUserByUsername(id)).thenReturn(dormantUser);
        when(dormantUser.getUserStatus()).thenReturn("DORMANT");
        when(dormantUser.getUserId()).thenReturn(id);

        when(redisTemplate.opsForValue()).thenReturn(valueOperations);

        assertThrows(UserDormantException.class, () -> authService.login(id, pw));

        verify(valueOperations, times(1)).set(eq(id), anyString(), any(Duration.class));

        ArgumentCaptor<MessagePayload> captor = ArgumentCaptor.forClass(MessagePayload.class);
        verify(doorayAdapter, times(1)).sendMessage(captor.capture());

        MessagePayload payload = captor.getValue();
        assertEquals("BeanSolid", payload.getBotName());
        assertTrue(payload.getText().startsWith(id + "님"));
        assertEquals(1, payload.getAttachments().size());
        assertEquals("인증 요청", payload.getAttachments().getFirst().getTitle());
    }



    @Test
    @DisplayName("휴면 사용자 인증 코드 검증 시 Redis에 코드가 없는 경우 예외 발생")
    void verifyDormantUserCode_codeNotInRedis_throwsException() {
        DormantUserVerificationRequestDto dto = mock(DormantUserVerificationRequestDto.class);
        when(dto.userId()).thenReturn("user123");
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get("user123")).thenReturn(null);

        assertThrows(VerificationCodeException.class, () -> authService.verifyDormantUserCode(dto));
    }

    @Test
    @DisplayName("휴면 사용자 인증 코드 불일치")
    void verifyDormantUserCode_codeNotMatch_returnsFalse() {
        DormantUserVerificationRequestDto dto = mock(DormantUserVerificationRequestDto.class);
        when(dto.userId()).thenReturn("user123");
        when(dto.verificationCode()).thenReturn("wrong");
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get("user123")).thenReturn("correct");
        assertFalse(authService.verifyDormantUserCode(dto));
    }

    @Test
    @DisplayName("휴면 사용자 인증 코드 검증 성공")
    void verifyDormantUserCode_success_setsActiveAndReturnsTrue() {
        DormantUserVerificationRequestDto dto = mock(DormantUserVerificationRequestDto.class);
        when(dto.userId()).thenReturn("user123");
        when(dto.verificationCode()).thenReturn("123456");
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get("user123")).thenReturn("123456");

        boolean result = authService.verifyDormantUserCode(dto);

        assertTrue(result);
        verify(userAdapter).updateStatus("user123", "ACTIVE");
        verify(redisTemplate).delete("user123");
    }

    @Test
    @DisplayName("예상치 못한 예외 발생 시 비밀번호 검증 실패")
    void verifyPassword_unexpectedException_returnsFalse() {
        String userId = "user123";
        String pw = "pw";
        when(userAdapter.getUserByUsername(userId)).thenThrow(new RuntimeException("Unexpected"));

        boolean result = authService.verifyPassword(userId, pw);

        assertFalse(result);
    }



}