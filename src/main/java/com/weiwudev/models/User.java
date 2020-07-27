package com.weiwudev.models;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Document(collection = "login")
public class User {

    @Id
    private String id;

    @Indexed(unique=true)
    private String username;

    private String password;

    private List<String> roles;

    public UserDetails toUserDetails(){
        return new MyUserDetails(username,password, roles);
    }

}
