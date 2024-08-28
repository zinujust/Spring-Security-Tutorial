package app.zinu.spring_security.securityConfig;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {
    
    @Autowired
    DataSource dataSource;

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
                .password(passwordencoder().encode("password"))
                .roles("USER")
                .build();
                
        UserDetails admin = User.withUsername("admin")
                .password(passwordencoder().encode("password2"))
                .roles("ADMIN")
                .build();
        
        JdbcUserDetailsManager userDetailsmanager = new JdbcUserDetailsManager(dataSource);

        userDetailsmanager.createUser(user1);
        userDetailsmanager.createUser(admin);

        return userDetailsmanager;
        //return new InMemoryUserDetailsManager(user1, admin);
    }

    @Bean
    public PasswordEncoder passwordencoder() {
        return new BCryptPasswordEncoder();
    }
}
