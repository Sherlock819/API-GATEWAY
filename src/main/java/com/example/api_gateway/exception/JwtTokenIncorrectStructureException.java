package com.example.api_gateway.exception;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.io.Serial;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class JwtTokenIncorrectStructureException extends RuntimeException {
    @Serial
    private static final long serialVersionUID = 1L;
    private String message;
    private static final Logger logger = LoggerFactory.getLogger(JwtTokenIncorrectStructureException.class);

    public JwtTokenIncorrectStructureException(String message) {
        super(message);
        this.message = message;
        logger.error("{}: {}", this.getClass().getName(), message);
    }
}
