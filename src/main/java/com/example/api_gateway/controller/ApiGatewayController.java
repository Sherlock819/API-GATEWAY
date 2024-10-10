package com.example.api_gateway.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController("/gateway")
public class ApiGatewayController {


    @GetMapping("/userDetails/{email}")
    public String getUserDetails(@PathVariable("email") String email) {
        return "HELLO - "+email;
    }
}
