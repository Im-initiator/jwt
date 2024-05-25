package com.leminhtien.jwt.auth;


import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    @Autowired
    private final AuthenticationService authenticationService;

    @PostMapping("/register")
    ResponseEntity<AuthenticationResponse> register(
            @RequestBody RegisterRequest request
    ){
        AuthenticationResponse au = authenticationService.register(request);
    //    System.out.println("--------------------------------"+ SecurityContextHolder.getContext().getAuthentication());
        return ResponseEntity.ok(au);
    }
    @PostMapping("/authenticated")
    ResponseEntity<AuthenticationResponse> login(
            @RequestBody AuthenticationRequest request
    ){
        AuthenticationResponse au = authenticationService.authentication(request);
   //     System.out.println("--------------------------------"+ SecurityContextHolder.getContext().getAuthentication());
        return ResponseEntity.ok(au);
    }

    @PostMapping("/refresh-token")
    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        authenticationService.refreshToken(request,response);
    }



}
