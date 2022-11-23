package com.ansv.app2.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController()
@RequestMapping("/app2/api")
public class Test2Controller {

    @GetMapping("/test1")
    public String test1() {
        return "app 2 - test1";
    }

    @GetMapping("/test2")
    public String test2() {
        return "app 2 - test2";
    }
    
}
