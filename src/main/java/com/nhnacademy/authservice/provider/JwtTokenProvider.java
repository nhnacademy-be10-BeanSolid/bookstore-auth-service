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
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Component
public class JwtTokenProvider {
    private final SecretKey key;
    private static final long ACCESS_TOKEN_EXPIRATION = 1000 * 60 * 30; // 30분
    private static final long REFRESH_TOKEN_EXPIRATION = 1000 * 60 * 60 * 24 * 7; // 7일

    public JwtTokenProvider(@Value("${jwt.secret}") String secretKey) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    // Access Token 생성
    public String generateToken(UserDetails userDetails) {
        String authorities = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        Date now = new Date();
        Date expiry = new Date(now.getTime() + ACCESS_TOKEN_EXPIRATION);

        return Jwts.builder()
                .subject(userDetails.getUsername())
                .claim("auth", authorities)
                .issuedAt(now)
                .expiration(expiry)
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }

    // Refresh Token 생성
    public String generateRefreshToken(UserDetails userDetails) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + REFRESH_TOKEN_EXPIRATION);

        return Jwts.builder()
                .subject(userDetails.getUsername())
                .issuedAt(now)
                .expiration(expiry)
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }

    // 토큰 유효성 검증
    public boolean validateToken(String token) {
        try {
            parseClaims(token); // 서명, 만료 등 검증
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            log.debug("Invalid JWT: {}", e.getMessage());
            return false;
        }
    }

    // Claims 추출 (검증은 별도)
    public Claims parseClaims(String token) {
        return Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload();
    }

    // Username 추출
    public String getUsernameFromToken(String token) {
        return parseClaims(token).getSubject();
    }

    // 권한 추출
    public List<String> getAuthoritiesFromToken(String token) {
        Claims claims = parseClaims(token);
        String auth = claims.get("auth", String.class);
        if (auth == null) return List.of();
        return Arrays.asList(auth.split(","));
    }

    public String generateTemporaryToken(String provider, String idNo) {
        // 임시 토큰 만료 시간: 10분
        long tempTokenExpiration = 1000 * 60 * 10;

        Date now = new Date();
        Date expiry = new Date(now.getTime() + tempTokenExpiration);

        return Jwts.builder()
                .subject(provider + ":" + idNo)
                .claim("provider", provider)
                .claim("idNo", idNo)
                .claim("type", "TEMP")
                .issuedAt(now)
                .expiration(expiry)
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }

    public Map<String, Object> parseTemporaryToken(String tempJwt) {
        try {
            Claims claims = parseClaims(tempJwt);

            // 토큰 타입 검증 (TEMP 여부 확인)
            String tokenType = claims.get("type", String.class);
            if(!"TEMP".equals(tokenType)) {
                throw new JwtException("Invalid token type");
            }

            return new HashMap<>(claims);
        } catch (JwtException | IllegalArgumentException e) {
            throw new JwtException("Invalid or expired temporary token: " + e.getMessage(), e);
        }
    }

}
