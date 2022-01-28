package com.example.reactivewebsecuritydemo;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
public class GreetingService {

    public Mono<String> userGreeting(Mono<String> name)
    {
        return name.map(n -> String.format("¯\\_( ͡❛ ͜ʖ ͡❛)_/¯ Greetings User %s ! ",n));
    }

    public Mono<String> adminGreeting(Mono<String> name)
    {
        return name.map(n -> String.format("\uD83D\uDE4F Greetings Admin %s ! ",n));
    }

    @PreAuthorize("hasRole('ADMIN')")
    public Mono<String>  specialGreeting(Mono<String> name) {
        return name.map(n -> String.format("\uD83C\uDFB8 Special Greetings %s ! ",n));
    }
}
