package com.weiwudev.controllers;

import com.weiwudev.models.User;
import com.weiwudev.repositories.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.List;


@RestController
public class RegistrationController {


    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public RegistrationController(UserRepository userRepository, PasswordEncoder passwordEncoder){
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/register")
    public Mono<ResponseEntity<String>> register(@RequestBody User user) {

        if (user.getId() != null) {
            user.setId(null);
        }

        List<String> roles = user.getRoles();
        for (String role : roles) {
            if (!role.equals("ROLE_USER")) {
                roles.remove(role);
            }
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRoles(roles);
        /*
        return userRepository.findByUsername(user.getUsername())
                .flatMap(userDetails -> Mono.just(ResponseEntity.status(HttpStatus.CONFLICT).body("username already exist")))
                .switchIfEmpty(userRepository.save(user).flatMap(acc -> Mono.just(ResponseEntity.status(HttpStatus.OK).body(acc.getId()))));
         */
        return userRepository.save(user).flatMap(acc -> Mono.just(ResponseEntity.status(HttpStatus.OK).body(acc.getId()))).onErrorReturn(
                ResponseEntity.status(HttpStatus.CONFLICT).body("username already exist"));
    }

}
