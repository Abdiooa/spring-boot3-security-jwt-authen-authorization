package com.aoo.springboot.authsecurity.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
//@RequestMapping("/api/v1/demo")
//@CrossOrigin(origins = "http://localhost:8050",
//        maxAge = 3600, allowCredentials = "true")
public class TestController {
    @GetMapping
    public ResponseEntity<String> sayHello(){

        return ResponseEntity.ok("Hello from secured endpoint");
    }
}
