package app.zinu.spring_security.securityConfig;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(requests -> 
                requests.requestMatchers("/h2-console/**").permitAll()
                .anyRequest().authenticated()) // Authorize all requests
            .httpBasic(httpBasic -> {}) // Enable HTTP Basic authentication with default settings
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // Stateless session management
            .userDetailsService(userDetailsService())
            .headers(headers -> headers
                .frameOptions(frameOptions -> frameOptions.sameOrigin()));
            http.csrf(csrf -> csrf.disable());
        return http.build();
    }

    public UserDetailsService userDetailsService(){
        UserDetails user1 = User.withUsername("user1")
                .password("{noop}password")
                .roles("USER")
                .build();
                
        UserDetails admin = User.withUsername("admin")
                .password("{noop}password2")
                .roles("ADMIN")
                .build();
        

        return new InMemoryUserDetailsManager(user1, admin);
    }
}
