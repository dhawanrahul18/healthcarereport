package com.example.demo.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.TimeZone;

@Service
public class JwtAuthenticationService {
    private AuthenticationManager authenticationManager;

    private final String SECRET_KEY = "SecretKey";

    public JwtAuthenticationService(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    public JwtTokenResponse authenticate(JwtTokenRequest tokenRequest, String url, TimeZone timeZone) throws AuthenticationException {
        UserDetails userDetails = managerAuthentication(tokenRequest.getUsername(), tokenRequest.getPassword());

        String token = generateToken(userDetails.getUsername(), url, timeZone);

        return new JwtTokenResponse(token);
    }

    private UserDetails managerAuthentication(String username, String password) throws AuthenticationException
    {
        Authentication authenticate = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));

        return (UserDetails) new User((String) authenticate.getPrincipal(), password, authenticate.getAuthorities());
    }

    private String generateToken(String username, String url, TimeZone timeZone)
    {
        try
        {
            Instant now = Instant.now();

            ZonedDateTime zonedDateTimeNow = ZonedDateTime.ofInstant(now, ZoneId.of(timeZone.getID()));

            Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY);
            String token = JWT.create()
                    .withIssuer(url)
                    .withSubject(username)
                    .withIssuedAt(Date.from(zonedDateTimeNow.toInstant()))
                    .withExpiresAt(Date.from(zonedDateTimeNow.plusMinutes(10).toInstant()))
                    .sign(algorithm);

            return token;
        }
        catch (JWTCreationException e)
        {
            e.printStackTrace();
            throw new JWTCreationException("Exception creating token", e);
        }
    }
}