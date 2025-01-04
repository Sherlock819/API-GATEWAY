package com.example.api_gateway.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(value = JwtTokenIncorrectStructureException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public @ResponseBody ErrorResponse handleException(JwtTokenIncorrectStructureException ex) {
        return new ErrorResponse(HttpStatus.UNAUTHORIZED.value(), ex.getMessage());
    }

    @ExceptionHandler(value = JwtTokenMissingException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED) // 409 Conflict
    public @ResponseBody ErrorResponse handleException(JwtTokenMissingException ex) {
        return new ErrorResponse(HttpStatus.UNAUTHORIZED.value(), ex.getMessage());
    }

    @ExceptionHandler(value = JwtTokenMalformedException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED) // 409 Conflict
    public @ResponseBody ErrorResponse handleException(JwtTokenMalformedException ex) {
        return new ErrorResponse(HttpStatus.UNAUTHORIZED.value(), ex.getMessage());
    }
}
