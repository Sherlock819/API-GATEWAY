package com.example.api_gateway.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
public class AuthManager implements ReactiveAuthenticationManager {
    private static final Logger log = LoggerFactory.getLogger(AuthManager.class);

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        try {
            String token = authentication.getCredentials().toString();

            if (jwtTokenProvider.validateToken(token)) {
                String email = jwtTokenProvider.getEmailFromToken(token);
                List<GrantedAuthority> authorities = jwtTokenProvider.getAuthoritiesFromToken(token);
                log.info("Successfully authenticated user: {}", email);
                return Mono.just(new UsernamePasswordAuthenticationToken(email, null, authorities));
            }

            log.warn("Token validation failed");
            return Mono.error(new BadCredentialsException("Invalid JWT token"));

        } catch (Exception e) {
            log.error("Authentication error: {}", e.getMessage());
            return Mono.error(new BadCredentialsException("Authentication failed: " + e.getMessage()));
        }
    }
}