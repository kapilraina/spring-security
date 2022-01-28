package com.example.reactivewebsecuritydemo;

import com.example.reactivewebsecuritydemo.model.CustomUserDetails;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.security.Principal;
import java.util.Date;
import java.util.stream.Collectors;

@RestController
public class RestControllers {
    @Autowired
    GreetingService greetingService;
    
    @Autowired
    JwtTokenUtils jwtutils;

    @GetMapping("/user")
    public Mono<String> greetUser(Mono<Principal> principal)
    {
        Mono<String> userGreeting =
                principal.flatMap(p -> greetingService.userGreeting(Mono.just(p.getName())));

        return userGreeting;
    }

    @GetMapping("/admin")
    public Mono<String> greetAdmin(Mono<Principal> principal)
    {
        Mono<String> userGreeting =
                principal.flatMap(p -> greetingService.adminGreeting(Mono.just(p.getName())));

        return userGreeting;
    }

    @GetMapping("/public")
    public Mono<String> publicEndoint()
    {
       return Mono.just("This is a public message and does not need any authentication and hasnt passed any filters");

    }

    @GetMapping("/special")
    public Mono<String> greetSpecial(Mono<Principal> principal)
    {
        Mono<String> userGreeting =
                principal.flatMap(p -> greetingService.specialGreeting(Mono.just(p.getName())));

        return userGreeting;
    }

    /**
     * If the request passed SecurityWebFilterChain successfully, the WebFilterChainServerAuthenticationSuccessHandler pass the request to POST /login controller.
     * @param exchange
     * @return
     */

    @PostMapping("/login")
    public Mono<ResponseEntity<String>> login(ServerWebExchange exchange, Authentication authentication)
    {
        UserDetails principal = (UserDetails) authentication.getPrincipal();
       /* return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .map(Authentication::getPrincipal)
                .cast(CustomUserDetails.class)
                .doOnNext(userDetails -> {
                    addTokenHeader(exchange.getResponse(), userDetails);
                }).map(customUserDetails -> customUserDetails.getUsername());*/

       return  Mono.just(generateJwt(principal))
                .map(token ->
                    ResponseEntity.ok().header(HttpHeaders.SET_COOKIE,"jwt_cookie="+token)
                            .header("auth_jwt",token)
                            .body("Hi "+ principal.getUsername() + ". You logged in at "+ new Date())
                );
    }

    private String generateJwt( UserDetails userDetails)  {
        String role_claims = userDetails.getAuthorities().stream()
                .map(ga -> ga.getAuthority())
                .collect(Collectors.joining(","));

        return jwtutils.generateToken(userDetails);

    }
}
