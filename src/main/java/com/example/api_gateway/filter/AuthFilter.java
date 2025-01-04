package com.example.api_gateway.filter;


import com.example.api_gateway.exception.JwtTokenIncorrectStructureException;
import com.example.api_gateway.security.JwtUtil;
import com.example.api_gateway.security.RouteValidator;
import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class AuthFilter extends AbstractGatewayFilterFactory<AuthFilter.Config> {

    @Autowired
    private RouteValidator routeValidator;

    @Autowired
    private JwtUtil jwtUtil;

    public AuthFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            System.out.println("Request URI: " + exchange.getRequest().getURI());
            System.out.println("Headers: " + exchange.getRequest().getHeaders());
            if (routeValidator.isSecured.test(exchange.getRequest())) {
                if (this.isAuthMissing(exchange.getRequest())) {
                    return this.onError(exchange, HttpStatus.UNAUTHORIZED);
                }

                final String token = this.getAuthHeader(exchange.getRequest());

                if (!jwtUtil.isValid(token)) {
                    return this.onError(exchange, HttpStatus.UNAUTHORIZED);
                }

                this.updateRequest(exchange, token);
            }
            return chain.filter(exchange);
        });
    }

    private Mono<Void> onError(ServerWebExchange exchange, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        return response.setComplete();
    }

    private String getAuthHeader(ServerHttpRequest request) {
        String[] parts = request.getHeaders().getOrEmpty("Authorization").get(0).split(" ");
        if (parts.length != 2 || !"Bearer".equals(parts[0])) {
            throw new JwtTokenIncorrectStructureException("Incorrect Authentication Structure");
        }
        return parts[1];
    }

    private boolean isAuthMissing(ServerHttpRequest request) {
        return !request.getHeaders().containsKey("Authorization");
    }

    private void updateRequest(ServerWebExchange exchange, String token) {
        Claims claims = jwtUtil.getAllClaimsFromToken(token);
        exchange.getRequest().mutate()
                .header("email", String.valueOf(claims.get("email")))
                .build();
    }

    public static class Config {

    }
}
