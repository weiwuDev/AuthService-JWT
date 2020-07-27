package com.weiwudev.models;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import java.security.SecureRandom;
import java.util.Date;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "refresh_tokens")
public class RefreshToken {
    @Id
    private String token;

    private String username;

    private Date created;

    @Field
    @Indexed(expireAfterSeconds = 1)
    private Date expires;


    public RefreshToken generateNewToken() {
        token = generateRandomSpecialCharacters(64);
        return this;
    }

    public Boolean isTokenExpired() {
        return expires.before(new Date());
    }

    private String generateRandomSpecialCharacters(int length) {
        char[] possibleCharacters = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789~`!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?").toCharArray();

        return RandomStringUtils.random(length, 0, possibleCharacters.length - 1, false, false, possibleCharacters, new SecureRandom());
    }
}
