package com.example.jwt.controller;

import com.example.jwt.auth.ApplicationUserService;
import com.example.jwt.model.JwtRequest;
import com.example.jwt.model.JwtResponse;
import com.example.jwt.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
public class HomeController {

    private JwtUtil jwtUtil;
    private AuthenticationManager authenticationManager;
    private ApplicationUserService applicationUserService;

    @Autowired
    public HomeController(JwtUtil jwtUtil, AuthenticationManager authenticationManager, ApplicationUserService applicationUserService) {
        this.jwtUtil = jwtUtil;
        this.authenticationManager = authenticationManager;
        this.applicationUserService = applicationUserService;
    }

    @GetMapping("/api/")
    public String home() {
        System.out.println("hello there");
        return "Hello There!";
    }

    @PostMapping("/user/login")
    public JwtResponse authenticate(@RequestBody JwtRequest jwtRequest) throws Exception {
        System.out.println("CALL /user/login");
        try {
            authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                    jwtRequest.getUsername(),
                    jwtRequest.getPassword()
                )
            );
        }
        catch (BadCredentialsException e) {
            throw new Exception("Invalid Credentials", e);
        }

        // Get the UserDetails to be added to the JWT Token
        final UserDetails userDetails = applicationUserService.loadUserByUsername(jwtRequest.getUsername());

        // Add the UserDetails to the token
        final String jwtToken = jwtUtil.generateToken(userDetails);

        // Add the token to the Response
        return new JwtResponse(jwtToken);

    }

}
