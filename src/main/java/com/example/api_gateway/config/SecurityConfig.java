package com.example.api_gateway.config;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Autowired
    private AuthFilter authFilter;

    @Autowired
    private AuthManager authenticationManager;

    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

    @Bean
    public SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http, AuthConverter authConverter, AuthManager authManager) throws Exception {
        AuthenticationWebFilter authenticationWebFilter = new AuthenticationWebFilter(authManager);
        authFilter.setServerAuthenticationConverter(authConverter);
        http.csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(auth -> auth
                        .pathMatchers("/user/auth/**", "/user/h2-console/**", "/restaurant/h2-console/**").permitAll() // Allow public access to certain endpoints
                        .anyExchange().authenticated() // All other requests need to be authenticated
                )
//                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .headers(headerSpec -> headerSpec.frameOptions(ServerHttpSecurity.HeaderSpec.FrameOptionsSpec::disable))
                .addFilterAt(authFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .exceptionHandling(exceptionHandlingSpec ->
                        exceptionHandlingSpec.authenticationEntryPoint((exchange, e) -> {
                            logger.error("Authentication error - -: {}", e.getMessage());
                            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                            return exchange.getResponse().setComplete();
                        })
                );

        return http.build();
    }
}
