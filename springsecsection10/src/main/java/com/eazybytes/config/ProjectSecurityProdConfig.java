package com.eazybytes.config;

import com.eazybytes.exceptionHandling.CustomAccessDeniedHandler;
import com.eazybytes.exceptionHandling.CustomBasicAuthenticationEntryPoint;
import com.eazybytes.filter.CorsConfigFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@Profile("prod")
public class ProjectSecurityProdConfig {
  @Bean
  SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    http
        .cors(cors -> cors.configurationSource(new CorsConfigFilter()))
        .sessionManagement(smc -> smc.invalidSessionUrl("/invalidSession")
            .maximumSessions(3).maxSessionsPreventsLogin(true))
        .requiresChannel(rcc -> rcc.anyRequest().requiresSecure()) // Only HTTPS
        .csrf( csrfConfig -> csrfConfig.disable())
        .authorizeHttpRequests((requests) -> requests
          .requestMatchers("/myAccount","/myBalance","myLoans", "/user").authenticated()
          .requestMatchers("notices","/contact","/error", "/register", "invalidSession").permitAll()
    );
    http.formLogin(withDefaults());
    http.httpBasic(hbc -> hbc.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint()));
    http.exceptionHandling(ehc -> ehc.accessDeniedHandler(new CustomAccessDeniedHandler()));
    return http.build();
  }
  @Bean
  public PasswordEncoder passwordEncoder(){
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
  }
  /**
   * From Spring Security 6.3version
   * @return
   */
  @Bean
  public CompromisedPasswordChecker compromisedPasswordChecker(){
    return new HaveIBeenPwnedRestApiPasswordChecker();
  }
}