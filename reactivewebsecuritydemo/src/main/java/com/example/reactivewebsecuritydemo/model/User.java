package com.example.reactivewebsecuritydemo.model;

import lombok.*;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@ToString
public class User {

    private String username;
    private String password;
    private Collection<String> roles;
}
