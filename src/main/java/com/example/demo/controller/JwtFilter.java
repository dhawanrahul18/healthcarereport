package com.example.demo.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import jakarta.servlet.http.Cookie;

import java.io.IOException;
import java.util.*;

public class JwtFilter extends OncePerRequestFilter
{
    private final String SECRET_KEY = "SecretKey";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        Cookie tokenCookie = null;
        if (request.getCookies() != null)
        {
            for (Cookie cookie : request.getCookies())
            {
                if (cookie.getName().equals("accessToken"))
                {
                    tokenCookie = cookie;
                    break;
                }
            }
        }

        if (tokenCookie != null)
        {
            cookieAuthentication(tokenCookie);
        }

        filterChain.doFilter(request, response);
    }

    private void cookieAuthentication(Cookie cookie)
    {
        UsernamePasswordAuthenticationToken auth = getTokenAuthentication(cookie.getValue());

        SecurityContextHolder.getContext().setAuthentication(auth);
    }

    private UsernamePasswordAuthenticationToken getTokenAuthentication(String token)
    {
        DecodedJWT decodedJWT = decodeAndVerifyJwt(token);

        String subject = decodedJWT.getSubject();

        Set<SimpleGrantedAuthority> simpleGrantedAuthority = Collections.singleton(new SimpleGrantedAuthority("USER"));

        return new UsernamePasswordAuthenticationToken(subject, null, simpleGrantedAuthority);
    }

    private DecodedJWT decodeAndVerifyJwt(String token)
    {
        DecodedJWT decodedJWT = null;
        try
        {
            JWTVerifier verifier = JWT.require(Algorithm.HMAC256(SECRET_KEY))
                    .build();

            decodedJWT = verifier.verify(token);

        } catch (JWTVerificationException e)
        {
            e.printStackTrace();
            //Invalid signature/token expired
        }

        return decodedJWT;
    }
}

//or load from other source
//public class JwtFilter extends OncePerRequestFilter
//{
//    private final String SECRET_KEY = ApplicationConstants.SECRET_KEY;
//}