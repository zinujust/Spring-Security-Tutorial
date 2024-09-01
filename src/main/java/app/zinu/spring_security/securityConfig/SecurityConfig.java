package app.zinu.spring_security.securityConfig;

import app.zinu.spring_security.Jwt.AuthEntryPointJwt;
import app.zinu.spring_security.Jwt.AuthTokenFilter;
import javax.sql.DataSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

  @Autowired DataSource dataSource;

  @Autowired private AuthEntryPointJwt unauthorizedHandler;

  @Bean
  public AuthTokenFilter authenticationJwtTokenFilter() {
    return new AuthTokenFilter();
  }

  @Bean
  public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
      throws Exception {
    http.authorizeHttpRequests(
            requests
            -> requests.requestMatchers("/h2-console/**")
                   .permitAll()
                   .requestMatchers("/signin")
                   .permitAll()
                   .anyRequest()
                   .authenticated()) // Authorize all requests
        //.httpBasic(httpBasic -> {}) // Enable HTTP Basic authentication with
        // default settings
        .sessionManagement(session
                           -> session.sessionCreationPolicy(
                               SessionCreationPolicy
                                   .STATELESS)) // Stateless session management
        // .userDetailsService(userDetailsService(dataSource))
        .exceptionHandling(
            exception
            -> exception.authenticationEntryPoint(unauthorizedHandler))
        .headers(
            headers
            -> headers.frameOptions(frameOptions -> frameOptions.sameOrigin()));
    http.csrf(csrf -> csrf.disable());
    http.addFilterBefore(authenticationJwtTokenFilter(),
                         UsernamePasswordAuthenticationFilter.class);
    return http.build();
  }

  @Bean
  public UserDetailsService userDetailsService(DataSource DataSource) {
    return new JdbcUserDetailsManager(dataSource);
  }

  @Bean
  public CommandLineRunner initData(UserDetailsService userDetailsService) {
    return arg -> {
      JdbcUserDetailsManager manager =
          (JdbcUserDetailsManager)userDetailsService;
      UserDetails user1 = User.withUsername("user1")
                              .password(passwordencoder().encode("password1"))
                              .roles("USER")
                              .build();

      UserDetails admin = User.withUsername("admin")
                              .password(passwordencoder().encode("password2"))
                              .roles("ADMIN")
                              .build();

      JdbcUserDetailsManager userDetailsManager =
          new JdbcUserDetailsManager(dataSource);
      userDetailsManager.createUser(user1);
      userDetailsManager.createUser(admin);
    };
  }

  @Bean
  public PasswordEncoder passwordencoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public AuthenticationManager
  authenticationManager(AuthenticationConfiguration builder) throws Exception {
    return builder.getAuthenticationManager();
  }
}
