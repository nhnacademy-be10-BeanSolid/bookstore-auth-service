package com.nhnacademy.authservice.domain;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserResponse {
    private String userId;
    private String userPassword;
    private String userName;
    private String userPhoneNumber;
    private String userEmail;
    private LocalDate userBirth;
    private int userPoint;
    private boolean isAuth;
    private String userStatus;
    private LocalDateTime lastLoginAt;
    private String userGradeName;
}

