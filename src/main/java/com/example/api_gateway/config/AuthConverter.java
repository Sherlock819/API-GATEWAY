package com.example.api_gateway.config;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class AuthConverter implements ServerAuthenticationConverter {
    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        String token = exchange.getRequest().getHeaders().getFirst("Authorization");
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);
            return Mono.just(SecurityContextHolder.getContext().getAuthentication());
        }
        return Mono.empty();
    }
}
