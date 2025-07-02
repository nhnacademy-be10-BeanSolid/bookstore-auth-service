package com.nhnacademy.authservice.util;

public class PhoneNumberUtils {

    private PhoneNumberUtils() {
        throw new IllegalStateException("Utility class");
    }

    public static String convertGlobalToKoreanPhoneNumber(String paycoPhoneNumber) {
        if(paycoPhoneNumber == null) {
            return null;
        }
        String digits = paycoPhoneNumber.replaceAll("\\D", "");
        if(digits.startsWith("82") && digits.length() >= 12) {
            digits = digits.substring(2);
            if(digits.startsWith("10")) {
                String formatted = "010" + digits.substring(2);
                if(formatted.length() == 11) {
                    return String.format("%s-%s-%s", formatted.substring(0, 3), formatted.substring(3, 7), formatted.substring(7));
                }
            }
        }

        return paycoPhoneNumber;
    }
}
