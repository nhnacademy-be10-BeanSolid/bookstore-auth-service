package com.nhnacademy.authservice.service;

import org.springframework.security.core.userdetails.UserDetails;

public interface AuthService {
    UserDetails authentication(String username, String password);
}
