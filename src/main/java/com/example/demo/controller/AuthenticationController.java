package com.example.demo.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.*;

import java.util.TimeZone;
@RestController
public class AuthenticationController {

    @Autowired
    JwtAuthenticationService authenticationService;

    @PostMapping("/authenticate")
    public ResponseEntity<String> createJwtAuthenticationToken(@RequestBody JwtTokenRequest tokenRequest, HttpServletRequest request, HttpServletResponse response, TimeZone timeZone) {
        try {
            JwtTokenResponse accessToken = authenticationService.authenticate(tokenRequest, String.valueOf(request.getRequestURL()), timeZone);

            HttpCookie accessTokenCookie = createCookieWithToken("accessToken", accessToken.getToken(), 10 * 60);


            return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, accessTokenCookie.toString()).body(accessTokenCookie.toString());
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
        }
    }


    @PostMapping("/testing")
    public ResponseEntity<String> testingAPI(HttpServletRequest request, HttpServletResponse response, TimeZone timeZone) {
        try {

            JSONObject jo = new JSONObject();
            jo.put("name", "jon doe");
            jo.put("age", "22");
            jo.put("city", "chicago");

            JSONObject jo1 = new JSONObject();
            jo1.put("name", "rahul");
            jo1.put("age", "27");
            jo1.put("city", "san jose");

            JSONArray ja = new JSONArray();
            ja.put(jo);
            ja.put(jo1);

            return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, request.getHeader(HttpHeaders.SET_COOKIE)).body(ja.toString());
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
        }
    }

    //creating cookie
    private HttpCookie createCookieWithToken(String name, String token, int maxAge) {
        return ResponseCookie.from(name, token)
                .httpOnly(true)
                .maxAge(maxAge)
                .path("/")
                .build();
    }
}
