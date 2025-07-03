package com.nhnacademy.authservice.service;

import com.nhnacademy.authservice.adapter.UserAdapter;
import com.nhnacademy.authservice.client.member.OAuth2MemberClient;
import com.nhnacademy.authservice.client.token.OAuth2TokenClient;
import com.nhnacademy.authservice.domain.request.OAuth2AdditionalSignupRequestDto;
import com.nhnacademy.authservice.domain.request.OAuth2UserCreateRequestDto;
import com.nhnacademy.authservice.domain.response.*;
import com.nhnacademy.authservice.exception.InvalidTokenException;
import com.nhnacademy.authservice.exception.UserWithdrawnException;
import com.nhnacademy.authservice.factory.OAuth2MemberClientFactory;
import com.nhnacademy.authservice.factory.OAuth2TokenClientFactory;
import com.nhnacademy.authservice.provider.JwtTokenProvider;
import com.nhnacademy.authservice.userdetails.CustomUserDetails;
import feign.FeignException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.time.LocalDate;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceImplTest {
    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private UserDetailsService userDetailsService;

    @Mock
    private JwtTokenProvider jwtTokenProvider;

    @Mock
    private OAuth2TokenClientFactory tokenClientFactory;

    @Mock
    private OAuth2MemberClientFactory memberClientFactory;

    @Mock
    private OAuth2TokenClient tokenClient;

    @Mock
    private OAuth2MemberClient memberClient;

    @Mock
    UserAdapter userAdapter;

    @InjectMocks
    AuthServiceImpl authService;

    @Mock
    UserDetails userDetails;

    @Mock
    Authentication authentication;

    @Test
    void login_success() {
        String id = "user";
        String pw = "pw";
        String accessToken = "access-token";
        String refreshToken = "refresh-token";

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(userDetails);
        when(jwtTokenProvider.generateToken(userDetails)).thenReturn(accessToken);
        when(jwtTokenProvider.generateRefreshToken(userDetails)).thenReturn(refreshToken);

        LoginResponseDto result = authService.login(id, pw);

        assertEquals(accessToken, result.accessToken());
        assertEquals(refreshToken, result.refreshToken());
    }

    @Test
    void authentication_success() {
        String username = "user";
        String password = "pw";
        when(authenticationManager.authenticate(any())).thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(userDetails);

        UserDetails result = authService.authentication(username, password);

        assertEquals(userDetails, result);
    }

    @Test
    void refreshToken_success() {
        String refreshToken = "refresh-token";
        String username = "user";
        String newAccessToken = "new-access";
        String newRefreshToken = "new-refresh";

        when(jwtTokenProvider.validateToken(refreshToken)).thenReturn(true);

        when(jwtTokenProvider.getUsernameFromToken(refreshToken)).thenReturn(username);
        when(userDetailsService.loadUserByUsername(username)).thenReturn(userDetails);

        when(jwtTokenProvider.generateToken(userDetails)).thenReturn(newAccessToken);
        when(jwtTokenProvider.generateRefreshToken(userDetails)).thenReturn(newRefreshToken);

        RefreshTokenResponseDto result = authService.refreshToken(refreshToken);

        assertEquals(newAccessToken, result.accessToken());
        assertEquals(newRefreshToken, result.refreshToken());
    }

    @Test
    void refreshToken_invalidToken_throwsException() {
        String refreshToken = "invalid";
        when(jwtTokenProvider.validateToken(refreshToken)).thenReturn(false);

        assertThrows(InvalidTokenException.class, () ->
                authService.refreshToken(refreshToken));
    }

    @Test
    void validateToken_success() {
        String token = "token";
        when(jwtTokenProvider.validateToken(token)).thenReturn(true);

        assertTrue(authService.validateToken(token));
    }

    @Test
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
    void parseToken_invalidToken_throwsException() {
        String token = "invalid-token";
        when(jwtTokenProvider.validateToken(token)).thenReturn(false);

        assertThrows(InvalidTokenException.class, () -> authService.parseToken(token));
    }

    @Test
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

        when(jwtTokenProvider.generateToken(any(CustomUserDetails.class))).thenReturn("access-token");
        when(jwtTokenProvider.generateRefreshToken(any(CustomUserDetails.class))).thenReturn("refresh-token");

        ResponseDto<?> response = authService.oauth2Login(provider, code);

        assertTrue(response.isSuccess());
        OAuth2LoginResponseDto loginResponseDto = (OAuth2LoginResponseDto) response.getData();
        assertEquals("access-token", loginResponseDto.getAccessToken());
        assertEquals("refresh-token", loginResponseDto.getRefreshToken());

    }

    @Test
    void completeOAuth2Signup_success_returnsTokens() {
        String tempJwt = "temp_jwt";
        OAuth2AdditionalSignupRequestDto additionalInfo = OAuth2AdditionalSignupRequestDto.builder()
                .name("Name")
                .mobile("010-1234-5678")
                .email("email@test.com")
                .birth(LocalDate.parse("1990-01-01"))
                .build();
        UserResponse savedUser = new UserResponse();

        when(jwtTokenProvider.parseTemporaryToken(tempJwt)).thenReturn(Map.of(
                "provider", "PAYCO",
                "idNo", "user123"
        ));

        when(userAdapter.saveOAuth2User(any(OAuth2UserCreateRequestDto.class))).thenReturn(savedUser);

        when(jwtTokenProvider.generateToken(any(CustomUserDetails.class))).thenReturn("access_token");
        when(jwtTokenProvider.generateRefreshToken(any(CustomUserDetails.class))).thenReturn("refresh_token");

        OAuth2LoginResponseDto response = authService.completeOAuth2Signup(tempJwt, additionalInfo);

        assertEquals("access_token", response.getAccessToken());
        assertEquals("refresh_token", response.getRefreshToken());
    }

    @Test
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
}