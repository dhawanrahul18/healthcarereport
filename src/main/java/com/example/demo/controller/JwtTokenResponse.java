package com.example.demo.controller;

public class JwtTokenResponse {

    String token;

    public JwtTokenResponse(String token) {
        this.token = token;
    }

    public String getToken() {
        return token;
    }
}
