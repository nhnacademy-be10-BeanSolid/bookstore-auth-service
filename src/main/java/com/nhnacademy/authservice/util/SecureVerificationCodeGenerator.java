package com.nhnacademy.authservice.util;

import java.security.SecureRandom;

public final class SecureVerificationCodeGenerator {
    private SecureVerificationCodeGenerator() {
        throw new IllegalStateException("Utility class");
    }

    private static final SecureRandom secureRandom = new SecureRandom();

    public static String generate6DigitCode() {
        int code = secureRandom.nextInt(1_000_000); // 0 ~ 999999
        return String.format("%06d", code);
    }
}
