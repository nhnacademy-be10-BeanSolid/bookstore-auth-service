package com.nhnacademy.authservice.domain.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
public class OAuth2MemberResponse {
    private Header header;
    private Data data;

    @lombok.Data
    public static class Header {
        private boolean isSuccessful;
        private int resultCode;
        private String resultMessage;
    }

    @lombok.Data
    public static class Data {
        private Member member;
    }

    @lombok.Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Member {
        private String idNo;
        private String email;
        private String mobile;
        private String maskedEmail;
        private String maskedMobile;
        private String name;
        private String genderCode;
        private String ageGroup;
        private String birthdayMMdd;
        private String birthday;
        private String ci;
        private String isForeigner;
        private String contactNumber;
        private Address address;
    }

    @lombok.Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Address {
        private String zipCode;
        private String address;
        private String addressDetail;
    }
}
