package com.example.api_gateway.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
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
    private static final Logger log = LoggerFactory.getLogger(AuthFilter.class);
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
        String path = exchange.getRequest().getPath().value();

        // Skip authentication for permitted paths
        if (isPermittedPath(path)) {
            return chain.filter(exchange);
        }

        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        // Check query parameter if header is not present
        if (authHeader == null) {
            authHeader = exchange.getRequest().getQueryParams().getFirst("token");
            if (authHeader != null) {
                authHeader = "Bearer " + authHeader.split("&")[0];
            }
        }

        log.info("Auth header: {}", authHeader);

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            return authManager.authenticate(new UsernamePasswordAuthenticationToken(null, token))
                    .flatMap(authentication -> securityContextRepository.save(exchange, new SecurityContextImpl(authentication)))
                    .then(chain.filter(exchange))
                    .onErrorResume(error -> {
                        log.error("Authentication error: {}", error.getMessage());
                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                        return exchange.getResponse().setComplete();
                    });
        }

        // Return 401 for protected paths without authentication
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }

    private boolean isPermittedPath(String path) {
        return path.startsWith("/user/auth/") ||
                path.startsWith("/user/h2-console/") ||
                path.startsWith("/h2-console/") ||
                path.startsWith("/restaurant/h2-console/");
    }
}