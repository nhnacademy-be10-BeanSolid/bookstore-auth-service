package com.nhnacademy.authservice.provider;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import static com.nhnacademy.authservice.provider.UserType.LOCAL;


/**
 * JWT 토큰 생성, 검증, 파싱을 담당하는 Provider 클래스
 * AccessToken, Refresh Token, Temporary Token을 지언합니다.
 */
@Slf4j
@Component
public class JwtTokenProvider {
    private final SecretKey key;

    // 토큰 만료 시간 상수
    private static final long ACCESS_TOKEN_EXPIRATION = 1000 * 60 * 30; // 30분
    private static final long REFRESH_TOKEN_EXPIRATION = 1000 * 60 * 60 * 24 * 7; // 7일
    private static final long TEMP_TOKEN_EXPIRATION = 1000 * 60 * 10; // 10분

    // 클레임 키 상수
    private static final String AUTHORITIES_KEY = "auth";
    private static final String USER_TYPE_KEY = "userType";
    private static final String PROVIDER_KEY = "provider";
    private static final String ID_NO_KEY = "idNo";
    private static final String TYPE_KEY = "type";
    private static final String TEMP_TOKEN_TYPE = "TEMP";

    /**
     * JWT 서명에 사용할 SecretKey를 초기화합니다.
     *
     * @param secretKey Base64로 인코딩된 시크릿 키
     */
    public JwtTokenProvider(@Value("${jwt.secret}") String secretKey) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    // ===== 토큰 생성 메서드 =====

    /**
     * Access Token을 생성합니다 (사용자 유형 지정).
     *
     * @param userDetails 사용자 상세 정보C
     * @param userType 사용자 유형 (LOCAL, OAUTH2)
     * @return 생성된 Access Token
     */
    public String generateAccessToken(UserDetails userDetails, UserType userType) {
        String authorities = extractAuthorities(userDetails);
        Date now = new Date();
        Date expiry = new Date(now.getTime() + ACCESS_TOKEN_EXPIRATION);

        return Jwts.builder()
                .subject(userDetails.getUsername())
                .claim(AUTHORITIES_KEY, authorities)
                .claim(USER_TYPE_KEY, userType.name())
                .issuedAt(now)
                .expiration(expiry)
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }

    /**
     * Refresh Token을 생성합니다.
     * 보안상 최소한의 정보만 포함됩니다.
     *
     * @param userDetails 사용자 상세 정보
     * @return 생성된 Refresh Token
     */
    public String generateRefreshToken(UserDetails userDetails, UserType userType) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + REFRESH_TOKEN_EXPIRATION);

        return Jwts.builder()
                .subject(userDetails.getUsername())
                .claim(USER_TYPE_KEY, userType.name())
                .issuedAt(now)
                .expiration(expiry)
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }

    /**
     * OAuth2 추가 회원가입용 임시 토큰을 생성합니다.
     *
     * @param provider OAuth2 제공자 (예: GOOGLE, KAKAO)
     * @param idNo 사용자 고유 식별번호
     * @return 생성된 임시 토큰
     */
    public String generateTemporaryToken(String provider, String idNo) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + TEMP_TOKEN_EXPIRATION);

        return Jwts.builder()
                .subject(provider + ":" + idNo)
                .claim(PROVIDER_KEY, provider)
                .claim(ID_NO_KEY, idNo)
                .claim(TYPE_KEY, TEMP_TOKEN_TYPE)
                .issuedAt(now)
                .expiration(expiry)
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }

    // ===== 토큰 검증 메서드 =====

    /**
     * 토큰의 유효성을 검증합니다.
     *
     * @param token 검증할 JWT 토큰
     * @return 토큰이 유요하면 true, 그렇지 않으면 false
     */
    public boolean validateToken(String token) {
        try {
            parseClaims(token); // 서명, 만료 등 검증
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            log.debug("Invalid JWT: {}", e.getMessage());
            return false;
        }
    }

    /**
     * 임시 토큰의 유효성을 검증합니다.
     * 토큰 타입이 TEMP 인지 확인합니다.
     *
     * @param token 검증할 임시 토큰
     * @return 임시 토큰이 유효하면 true, 그렇지 않으면 false
     */
    public boolean validateTemporaryToken(String token) {
        try {
            Claims claims = parseClaims(token);
            String tokenType = claims.get(TYPE_KEY, String.class);
            return TEMP_TOKEN_TYPE.equals(tokenType);
        } catch (JwtException | IllegalArgumentException e) {
            log.debug("Invalid temporary JWT: {}", e.getMessage());
            return false;
        }
    }

    // ===== 토큰 파싱 메서드 =====

    /**
     * 토큰에서 Claims를 추출합니다.
     * 토큰의 서명과 만료 시간을 검증합니다.
     *
     * @param token 파싱할 JWT 토큰
     * @return 토큰의 Claims 객체
     * @throws JwtException 토큰이 유효하지 않은 경우
     */
    public Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * 임시 토큰을 파싱하여 Claims를 반환합니다.
     * 먼저 토큰 유효성을 검증한 후 파싱합니다.
     *
     * @param tempJwt 파싱할 임시 JWT 토큰
     * @return 임시 토큰의 Claims 객체
     * @throws JwtException 토큰이 유효하지 않거나 임시 토큰 타입이 아닌 경우
     */
    public Claims parseTemporaryToken(String tempJwt) {
        if(!validateTemporaryToken(tempJwt)) {
            throw new JwtException("Invalid or expired temporary token");
        }

        return parseClaims(tempJwt);
    }

    // ===== 토큰 정보 추출 메서드 =====

    /**
     * 토큰에서 사용자명을 추출합니다.
     *
     * @param token JWT 토큰
     * @return 사용자명 (subject)
     */
    public String getUsernameFromToken(String token) {
        return parseClaims(token).getSubject();
    }

    /**
     * 토큰에서 권한 목록을 추출합니다.
     *
     * @param token JWT 토큰
     * @return 권한 목록 (쉼표로 구분된 문자열을 리스트로 변환)
     */
    public List<String> getAuthoritiesFromToken(String token) {
        Claims claims = parseClaims(token);
        String auth = claims.get("auth", String.class);
        if (auth == null) return List.of();
        return Arrays.asList(auth.split(","));
    }

    /**
     * 토큰에서 사용자 유형을 추출합니다.
     *
     * @param token JWT 토큰
     * @return 사용자 유형 (LOCAL, OAUTH2)
     */
    public UserType getUserTypeFromToken(String token) {
        Claims claims = parseClaims(token);
        String userTypeStr = claims.get(USER_TYPE_KEY, String.class);
        try {
            return UserType.valueOf(userTypeStr);
        } catch (IllegalArgumentException | NullPointerException e) {
            log.warn("Unknown userType in token: {}", userTypeStr);
            return LOCAL;
        }
    }

    // ===== 유틸리티 메서드 =====

    /**
     * UserDetails 에서 권한 문자열을 추출합니다.
     * 권한들을 쉼표로 구분된 문자열로 반환합니다.
     *
     * @param userDetails 사용자 상세 정보
     * @return 쉼표로 구분된 권한 문자열
     */
    private String extractAuthorities(UserDetails userDetails) {
        return userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
    }


}
