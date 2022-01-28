package com.example.reactivewebsecuritydemo;

import com.example.reactivewebsecuritydemo.model.CustomUserDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;


public class CustomUserDetailService implements ReactiveUserDetailsService {

    Map<String, UserDetails> users;

    public CustomUserDetailService(Map<String, UserDetails> users) {
        this.users = users;
    }

    public CustomUserDetailService() {
        super();
    }

    @Override
    public Mono<UserDetails> findByUsername(String username) {
        System.out.println(" FindUserByName : " + username);
        return Mono.just(username)
                .flatMap(user -> getuserdetails(user));
    }

    private Mono<UserDetails> getuserdetails(String user) {
        UserDetails userdetails = users.get(user);
        if (userdetails == null) {
            System.out.println("User " + user + " Not Found");
            return Mono.error(new UsernameNotFoundException("User " + user + " Not Found"));
        } else {
            System.out.println(" UserDetails  : " + userdetails);
            return Mono.just(userdetails);
        }
    }
}

