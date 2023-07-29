package com.example.demo.configuration;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import java.util.ArrayList;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String principal = (String) authentication.getPrincipal();
        String credential = (String)authentication.getCredentials();
        if( principal.equalsIgnoreCase("Rahul") && credential.equalsIgnoreCase("Dhawan")){
             return new UsernamePasswordAuthenticationToken(
                     principal, credential, new ArrayList<>());
        }else{
             throw new BadCredentialsException("could not login") ;
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
