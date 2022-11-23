package com.ansv.app1.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController()
@RequestMapping("/app1/api")
public class Test1Controller {

    @GetMapping("/test1")
    public String test1() {
        return "app 1 - test1";
    }

    @GetMapping("/test2")
    public String test2() {
        return "app 2 - test2";
    }
    
}
