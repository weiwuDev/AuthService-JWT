package com.weiwudev.services;

import com.sun.org.apache.xpath.internal.operations.Bool;
import com.weiwudev.models.RefreshToken;
import com.weiwudev.models.User;
import com.weiwudev.repositories.RefreshTokenRepository;
import com.weiwudev.repositories.UserRepository;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Duration;
import java.util.Base64;
import java.util.Date;

@Service
public class RefreshTokenService {

    @Value("${springboot-webflux-jwt.refresh_token.expiration}")
    private String expirationTime;

    @Autowired
    RefreshTokenRepository refreshTokenRepository;

    @Autowired
    UserRepository userRepository;

    public Mono<String> generateAndSave(String username){
        Long expirationTimeLong = Long.parseLong(expirationTime); //in second
        final Date createdDate = new Date();
        final Date expirationDate = new Date(createdDate.getTime() + expirationTimeLong * 1000);

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUsername(username);
        refreshToken.setCreated(createdDate);
        refreshToken.setExpires(expirationDate);
        return refreshTokenRepository.insert(refreshToken.generateNewToken()).retryWhen(Retry.fixedDelay(5, Duration.ofSeconds(5))).map(RefreshToken::getToken);
    }

    public Mono<Boolean> deleteToken(String token){
        return refreshTokenRepository.deleteById(new String(Base64.getDecoder().decode(token))).map(x -> true).defaultIfEmpty(false);
    }


    public Mono<User> validateToken(String token){
        return refreshTokenRepository.findById(new String(Base64.getDecoder().decode(token))).flatMap(refreshToken -> {
            if(!refreshToken.isTokenExpired()){
                return userRepository.findByUsername(refreshToken.getUsername());
            }else{
                return refreshTokenRepository.delete(refreshToken).then(Mono.empty());
            }
        }).switchIfEmpty(Mono.defer(() -> Mono.empty()));
    }

}
