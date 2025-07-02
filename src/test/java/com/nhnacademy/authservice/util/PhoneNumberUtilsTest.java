package com.nhnacademy.authservice.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PhoneNumberUtilsTest {

    @Test
    void testConvertGlobalToKoreanPhoneNumber_NullInput() {
        String phoneNumber = null;
        String result = PhoneNumberUtils.convertGlobalToKoreanPhoneNumber(phoneNumber);

        assertNull(result);
    }

    @Test
    void testConvertGlobalToKoreanPhoneNumber_AlreadyFormatted() {
        String input = "010-1234-5678";

        String result = PhoneNumberUtils.convertGlobalToKoreanPhoneNumber(input);

        assertEquals("010-1234-5678", result);
    }

    @Test
    void testConvertGlobalToKoreanPhoneNumber_GlobalFormat() {
        String input = "+82-10-1234-5678";

        String result = PhoneNumberUtils.convertGlobalToKoreanPhoneNumber(input);

        assertEquals("010-1234-5678", result);
    }

    @Test
    void testConvertGlobalToKoreanPhoneNumber_GlobalFormatWithoutDash() {
        String input = "821012345678";

        String result = PhoneNumberUtils.convertGlobalToKoreanPhoneNumber(input);

        assertEquals("010-1234-5678", result);
    }

    @Test
    void testConvertGlobalToKoreanPhoneNumber_NotMobileNumber() {
        String input = "+82-2-1234-5678";

        String result = PhoneNumberUtils.convertGlobalToKoreanPhoneNumber(input);

        assertEquals("+82-2-1234-5678", result);
    }

    @Test
    void testConvertGlobalToKoreanPhoneNumber_InvalidLength() {
        // Arrange
        String input = "+82-10-1234-567"; // 10자리 미만

        // Act
        String result = PhoneNumberUtils.convertGlobalToKoreanPhoneNumber(input);

        // Assert
        assertEquals("+82-10-1234-567", result);
    }
}