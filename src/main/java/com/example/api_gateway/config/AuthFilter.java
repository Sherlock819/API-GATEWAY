package com.example.api_gateway.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Component
public class AuthFilter extends AuthenticationWebFilter {


    private final AuthManager authManager;

    private final ServerSecurityContextRepository securityContextRepository;

    @Autowired
    public AuthFilter(AuthManager authManager,
                      ServerSecurityContextRepository securityContextRepository) {
        super(authManager);
        this.authManager = authManager;

        setSecurityContextRepository(securityContextRepository);
        this.securityContextRepository = securityContextRepository;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            return authManager.authenticate(new UsernamePasswordAuthenticationToken(null, token))
                    .flatMap(authentication -> securityContextRepository.save(exchange, new SecurityContextImpl(authentication)))
                    .then(chain.filter(exchange));
        }

        return chain.filter(exchange);
    }
}

