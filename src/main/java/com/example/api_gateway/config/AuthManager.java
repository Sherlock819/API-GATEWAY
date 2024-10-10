package com.example.api_gateway.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
public class AuthManager implements ReactiveAuthenticationManager {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) throws AuthenticationException {
        String token = authentication.getCredentials().toString();
        String email = jwtTokenProvider.getEmailFromToken(token);
        List<GrantedAuthority> authorities = jwtTokenProvider.getAuthoritiesFromToken(token);

        if (jwtTokenProvider.validateToken(token)) {
            return Mono.justOrEmpty(new UsernamePasswordAuthenticationToken(email, null, authorities));
        } else {
            throw new AuthenticationException("Invalid JWT token") {
            };
        }

    }
}