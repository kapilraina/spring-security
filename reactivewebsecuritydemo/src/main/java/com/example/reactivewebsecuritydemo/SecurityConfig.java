package com.example.reactivewebsecuritydemo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.WebFilterChainServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import reactor.core.publisher.Mono;

import java.util.Map;

@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
@Configuration
public class SecurityConfig {

    Jwttokenvalidationfilter jwttokenvalidationfilter;

    SecurityConfig(Jwttokenvalidationfilter jwttokenvalidationfilter) {

        this.jwttokenvalidationfilter = jwttokenvalidationfilter;
    }

    @Bean
    public SecurityWebFilterChain securitygWebFilterChain(
            ServerHttpSecurity httpsecurity) {

     /* HTTP Basic, default behaviour
        return httpsecurity.authorizeExchange()
                .anyExchange().authenticated()
                .and().build();*/
       /* // Default Form Login
        return httpsecurity.authorizeExchange()
                .anyExchange().authenticated()
                .and().formLogin()
                .and().build();*/

        // With Admin User Role Check
        /*return httpsecurity.authorizeExchange()
                .pathMatchers("/admin").hasAnyAuthority("ROLE_ADMIN")
                .anyExchange().authenticated()
                .and().formLogin()
                .and().build();*/

        SecurityWebFilterChain filterChain = httpsecurity.authorizeExchange()
                .pathMatchers(HttpMethod.DELETE).denyAll()
                .pathMatchers("/login", "/logout", "/favicon.ico", "/public").permitAll()
                .pathMatchers("/admin").hasAnyAuthority("ROLE_ADMIN")
                .anyExchange().authenticated()
                .and().formLogin()
                //.loginPage("/login") //default
                //.authenticationFailureHandler((exchange, exception) -> Mono.error(exception))
                .authenticationSuccessHandler(new WebFilterChainServerAuthenticationSuccessHandler())
                //  .and()
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .and()
                .addFilterAfter(jwttokenvalidationfilter, SecurityWebFiltersOrder.CSRF)
                .build();

        return filterChain;
        /**
         * AccessDeniedHandler - this handles issues like when a user not having required roles.
         * AuthenticationEntryPoint - this handles issues like when a user tries to access a resource without appropriate authentication elements.
         *
         * AuthenticationFailureHandler - this handles issues like when a user is not found(i.e. UsernameNotFoundException) or other exceptions thrown inside authentication provider. In fact, this handles other authentication exceptions that are not handled by AccessDeniedException and AuthenticationEntryPoint.
         *
         * AuthenticationSuccessHandler - this helps to do stuff like redirection after a user is successfully authenticated.
         */
    }

   /* @Bean
    public MapReactiveUserDetailsService minimaluserDetailsService() {
        UserDetails user = User
                .withUsername("user")
                .password(passwordEncoder().encode("password"))
                .roles("USER")
                .build();
        UserDetails admin = User
                .withUsername("admin")
                .password(passwordEncoder().encode("password"))
                .roles("ADMIN")
                .build();
        return new MapReactiveUserDetailsService(user,admin);
    }
    */


}
