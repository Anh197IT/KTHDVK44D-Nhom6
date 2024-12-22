package com.example.bths2.controller;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/hello")
public class HelloController {

    @GetMapping
    public String helloWorld() {
        return "Hello World!";
    }
}
