package com.example.reactivewebsecuritydemo;

import com.example.reactivewebsecuritydemo.model.CustomUserDetails;
import com.example.reactivewebsecuritydemo.model.User;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Configuration
public class DemoConfig {


    @Bean
    public Map<String, UserDetails> createSyntheticUsers(PasswordEncoder passwordEncoder)
    {

        User u1 = new User("jhon",passwordEncoder.encode("password"), List.of("USER","DEVELOPER"));
        User u2 = new User("jane",passwordEncoder.encode("password"), List.of("USER","DBA"));
        User u3 = new User("jim",passwordEncoder.encode("password"), List.of("USER","ADMIN"));
        Map<String,UserDetails> users = new HashMap<String,UserDetails>();
        users.put(u1.getUsername(),new CustomUserDetails(u1));
        users.put(u2.getUsername(),new CustomUserDetails(u2));
        users.put(u3.getUsername(),new CustomUserDetails(u3));
        return users;

    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        PasswordEncoderFactories.createDelegatingPasswordEncoder();
        return new BCryptPasswordEncoder();
    }

    @Bean
    public JwtTokenUtils jwtTokenUtils()
    {
        return new JwtTokenUtils();
    }
    @Bean
    public ReactiveUserDetailsService userDetailsService()
    {
        return new CustomUserDetailService(createSyntheticUsers(passwordEncoder()));
    }

    @Bean
    public Jwttokenvalidationfilter jwttokenvalidationfilter()
    {
        return new Jwttokenvalidationfilter(jwtTokenUtils(),userDetailsService());
    }
}
