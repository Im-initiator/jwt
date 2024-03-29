package com.leminhtien.jwt.demo;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/api/v1/demo-controller")
@RestController
public class DemoController {

    @GetMapping
    public ResponseEntity<String> sayHello(){
        System.out.println("--------------------------------"+ SecurityContextHolder.getContext().getAuthentication());
        return ResponseEntity.ok("Ok Hello Lê Minh Tiến");
    }
}
