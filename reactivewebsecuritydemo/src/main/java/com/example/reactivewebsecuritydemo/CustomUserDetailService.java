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

    public CustomUserDetailService(Map<String, UserDetails> users)
    {
        this.users = users;
    }

    public CustomUserDetailService() {
        super();
    }

    @Override
    public Mono<UserDetails> findByUsername(String username) {
        System.out.println(" FindUserByName : "+username);
        System.out.println(" UserDetails  : "+users.get(username));
        return Mono.just(username)
                .map(user -> users.get(user))
                .flatMap(userDetails -> {
                    if(userDetails==null)
                    {
                        System.out.println("User " + username + " Not Found");
                        return Mono.error(new UsernameNotFoundException("User " + username + " Not Found"));
                    }
                    return Mono.just(userDetails);
                }).map(userDetails -> userDetails);


    }
}
