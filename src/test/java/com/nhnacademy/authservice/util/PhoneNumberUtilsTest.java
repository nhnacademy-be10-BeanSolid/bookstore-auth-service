package com.nhnacademy.authservice.util;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;

class PhoneNumberUtilsTest {

    @ParameterizedTest(name = "[{index}] input: \"{0}\", expected: \"{1}\"")
    @CsvSource({
            ",", // null input -> expect null
            "'010-1234-5678', '010-1234-5678'", // already formatted
            "'+82-10-1234-5678', '010-1234-5678'", // global format
            "'821012345678', '010-1234-5678'", // global format without dash
            "'+82-2-1234-5678', '+82-2-1234-5678'", // not mobile number
            "'+82-10-1234-567', '+82-10-1234-567'" // invalid length
    })
    void testConvertGlobalToKoreanPhoneNumber(String input, String expected) {
        String result = PhoneNumberUtils.convertGlobalToKoreanPhoneNumber(input);
        assertEquals(expected, result);
    }
}