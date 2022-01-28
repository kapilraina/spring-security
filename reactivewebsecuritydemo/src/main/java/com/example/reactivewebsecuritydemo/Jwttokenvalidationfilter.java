package com.example.reactivewebsecuritydemo;


import io.jsonwebtoken.JwtException;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;

import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

public class Jwttokenvalidationfilter implements WebFilter {

    public static final String HEADER_PREFIX = "Bearer ";
    private JwtTokenUtils jwtUtils;
    private ReactiveUserDetailsService reactiveUserDetailsService;

    Jwttokenvalidationfilter(JwtTokenUtils jwtUtils, ReactiveUserDetailsService reactiveUserDetailsService) {
        this.jwtUtils = jwtUtils;
        this.reactiveUserDetailsService = reactiveUserDetailsService;
    }


    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String jwt;
        HttpHeaders headers = exchange.getRequest().getHeaders();
        final String requestTokenHeader = headers.get("Authorization") != null ? headers.get("Authorization").get(0) : "";

        if (StringUtils.hasText(requestTokenHeader)) {
            jwt = resolveTokenFromHeader(requestTokenHeader);
            System.out.println("Token Received From Header: " + jwt);

        } else {
            MultiValueMap<String, HttpCookie> cookies = exchange.getRequest().getCookies();
            HttpCookie jwt_cookie = cookies.getFirst("jwt_cookie");
            jwt = jwt_cookie != null ? jwt_cookie.getValue() : "";
            System.out.println("Token Received From Cookie: " + jwt);
        }

        if (StringUtils.hasText(jwt)) {
            System.out.println("Validating Token");

            return validatetoken(jwt, exchange, chain)
                    .onErrorResume(io.jsonwebtoken.MalformedJwtException.class, t -> minimalErrorHandling(exchange,t))
                    .onErrorResume(throwable -> resumetoNextFilter(throwable, exchange, chain))
                    .flatMap(m -> chain.filter(exchange));
        } else {
            System.out.println("No JWT Received in this request");

        }
        return chain.filter(exchange);
    }

    private Mono<Void> minimalErrorHandling(ServerWebExchange exchange,Throwable t) {
        System.out.println("Minimal Error Handling For Exception : "+t.getMessage());
        exchange.getResponse().setRawStatusCode(HttpStatus.UNAUTHORIZED.value());
        return exchange.getResponse().setComplete();

    }
    private Mono<Void> resumetoNextFilter(Throwable t, ServerWebExchange exchange, WebFilterChain chain) {

        System.out.println("Resuming to next filter For Exception : "+t.getMessage());
        return chain.filter(exchange);

    }

    private Mono<Void> validatetoken(String jwt, ServerWebExchange exchange, WebFilterChain chain) {
        System.out.println("validatetoken....");
        //String usernameFromToken = jwtUtils.getUsernameFromToken(jwt);
        return jwtUtils.getUsernameFromToken(jwt)
                .flatMap(tokenusername -> compareTokenAndFormUser(tokenusername, exchange, chain))
                .flatMap(tokenusername -> reactiveUserDetailsService.findByUsername(tokenusername))
                .flatMap(userDetails -> jwtUtils.validateToken(jwt, userDetails))
                .flatMap(validateduserDetails -> createunptoken(validateduserDetails, exchange, chain));
    }



    private Mono<String> compareTokenAndFormUser(String tokenusername, ServerWebExchange exchange, WebFilterChain chain) {
        System.out.println("Comparing Users from Token and Form, if any");
        Mono<MultiValueMap<String, String>> formData = exchange.getFormData();
        if (formData != null) {

            return formData.flatMap(mvMap -> {
                String username = mvMap.getFirst("username");
                System.out.println("Token Username : " + tokenusername + ".| Form UserName : " + username);
                if (username != null && !username.equalsIgnoreCase(tokenusername)) {
                    return Mono.error(new JwtException(" New User Login Detected. ReAuthenticate"));

                } else {
                    return Mono.just(tokenusername);

                }
            });


        }
        return Mono.just(tokenusername);

    }

    private Mono<Void> createunptoken(UserDetails userDetails, ServerWebExchange exchange, WebFilterChain chain) {
        System.out.println("createunptoken....");
        // TokenBasedAuthentication extends .AbstractAuthenticationToken
        UsernamePasswordAuthenticationToken unp = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        unp.setDetails(exchange.getRequest());
        System.out.println("Setting Auth in Security Context " + unp);
        return chain.filter(exchange).contextWrite(ReactiveSecurityContextHolder.withAuthentication(unp));
       /* ReactiveSecurityContextHolder
                .getContext()
                .map(sc -> setAuth(sc,unp))
                .flatMap(scvalidated -> scvalidated)
                .doOnNext(sc-> System.out.println("Security Context = "+ sc))
                .subscribe();

        return Mono.empty().then();*/


    }

    private Mono<SecurityContext> setAuth(SecurityContext securityContext, UsernamePasswordAuthenticationToken unp) {
        securityContext.setAuthentication(unp);
        return Mono.just(securityContext);

    }


    private Mono<Void> handleError(ServerWebExchange exchange, Exception ex) {
        return writeResponse(exchange, ex.getMessage());
    }

    private Mono<Void> handleError(ServerWebExchange exchange, Throwable ex) {
        return writeResponse(exchange, ex.getMessage());
    }

    private Mono<Void> writeResponse(ServerWebExchange exchange, String message) {
        exchange.getResponse().setRawStatusCode(HttpStatus.UNAUTHORIZED.value());
        exchange.getResponse().getHeaders().add("Content-Type", "application/json");
        return exchange
                .getResponse()
                .writeWith(
                        Flux.just(
                                exchange.getResponse().bufferFactory().wrap(message.getBytes(StandardCharsets.UTF_8))));
    }

    private String resolveTokenFromHeader(String bearerToken) {

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(HEADER_PREFIX)) {
            return bearerToken.substring(7).trim();
        }
        return "";
    }
}
