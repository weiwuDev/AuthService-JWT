package com.weiwudev.controllers;


import com.weiwudev.models.AuthRequest;
import com.weiwudev.models.AuthResponse;
import com.weiwudev.models.ResponseObject;
import com.weiwudev.repositories.UserRepository;
import com.weiwudev.services.RefreshTokenService;
import com.weiwudev.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.Base64;


@RestController
@RefreshScope
public class AuthController {

    @Value("${check.response.value}")
    private String checkResponse;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    RefreshTokenService refreshTokenService;

    @Autowired
    JwtUtil jwtUtil;

    @PostMapping("/login")
    public Mono<ResponseEntity<AuthResponse>> login(@RequestBody AuthRequest user, ServerHttpResponse response) {
        return userRepository.findByUsername(user.getUsername()).flatMap(userDetails -> {
            if (passwordEncoder.matches(user.getPassword(), userDetails.getPassword())) {
                return refreshTokenService.generateAndSave(userDetails.getUsername()).map(token -> {
                    response.addCookie(ResponseCookie.from("Refresh_Token", Base64.getEncoder().encodeToString(token.getBytes())).httpOnly(true).sameSite("None").build());
                    return ResponseEntity.status(HttpStatus.OK).body(new AuthResponse(jwtUtil.generateToken(userDetails)));
                });
            } else {
                return Mono.empty();
            }
        }).switchIfEmpty(Mono.defer(() -> {
            response.addCookie(ResponseCookie.from("Refresh", "").httpOnly(true).sameSite("None").maxAge(0).build());
            return Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new AuthResponse()));
        }));
    }


    @PutMapping("/logout")
    public Mono<ResponseEntity<ResponseObject>> logout(ServerHttpResponse response, @CookieValue(name = "Refresh_Token", required = true) String token) {
        return refreshTokenService.deleteToken(token).map(x -> {
            response.addCookie(ResponseCookie.from("Refresh_Token", "").httpOnly(true).sameSite("None").maxAge(0).build());
            return ResponseEntity.status(HttpStatus.OK).body(new ResponseObject("Logout Successful"));
        }).switchIfEmpty(Mono.defer(() -> Mono.just(ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ResponseObject("Logout Fail")))));
    }

    @PostMapping("/refresh")
    public Mono<ResponseEntity<AuthResponse>> refresh(@CookieValue(name = "Refresh_Token", required = true) String token, ServerHttpResponse response) {
        return refreshTokenService.validateToken(token)
                .map(userDetails -> ResponseEntity.status(HttpStatus.OK).body(new AuthResponse(jwtUtil.generateToken(userDetails))))
                .switchIfEmpty(Mono.defer(() -> {
                    response.addCookie(ResponseCookie.from("Refresh_Token", "").httpOnly(true).sameSite("None").maxAge(0).build());
                    return Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new AuthResponse()));
                }));
    }


    @GetMapping("/check")
    public Mono<ResponseEntity<ResponseObject>> checkAuth(WebSession webSession, ServerWebExchange exchange) {
        return Mono.just(ResponseEntity.status(HttpStatus.OK).body(new ResponseObject(checkResponse)));
    }

    @GetMapping("/checkno")
    public Mono<ResponseEntity<ResponseObject>> checkAuthNo(WebSession webSession, ServerWebExchange exchange) {
        return Mono.just(ResponseEntity.status(HttpStatus.OK).body(new ResponseObject(checkResponse)));
    }
}
