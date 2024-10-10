package com.example.api_gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.web.server.session.WebSessionManager;
import reactor.core.publisher.Mono;

@Configuration
public class SecurityContextConfig {

    @Bean
    public ServerSecurityContextRepository securityContextRepository() {
        return new WebSessionServerSecurityContextRepository();
    }

//    @Bean
//    public WebSessionManager webSessionManager() {
//        // Emulate SessionCreationPolicy.STATELESS
//        return exchange -> Mono.empty();
//    }
}

