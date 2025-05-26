package com.eazybytes.config;

import com.eazybytes.exceptionHandling.CustomAccessDeniedHandler;
import com.eazybytes.exceptionHandling.CustomBasicAuthenticationEntryPoint;
import com.eazybytes.filter.CorsConfigFilter;
import com.eazybytes.filter.CsrfCookieFilter;
import com.eazybytes.filter.RequestValidationBeforeFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

import static org.springframework.security.config.Customizer.withDefaults;

@SuppressWarnings("SpellCheckingInspection")
@Configuration
@Profile("!prod")
public class ProjectSecurityConfig {
  private final CorsConfigurationSource corsConfigurationSource;

  public ProjectSecurityConfig(CorsConfigurationSource corsConfigurationSource) {
    this.corsConfigurationSource = corsConfigurationSource;
  }

  @Bean
  SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    CsrfTokenRequestAttributeHandler csrfTokenRequestAttributeHandler = new CsrfTokenRequestAttributeHandler();
    http
        .securityContext(contextConfig -> contextConfig.requireExplicitSave(false))
        .sessionManagement(sessionConfig ->
            sessionConfig.sessionCreationPolicy(SessionCreationPolicy.ALWAYS)) // always create a session to be used to access resources
        .cors(cors -> cors.configurationSource(new CorsConfigFilter()))
        .csrf(csrfConfig -> csrfConfig.csrfTokenRequestHandler(csrfTokenRequestAttributeHandler)
            .ignoringRequestMatchers( "/contact","/register")
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
        .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
        .addFilterBefore(new RequestValidationBeforeFilter(), BasicAuthenticationFilter.class)
        .requiresChannel(rcc -> rcc.anyRequest().requiresInsecure()) // Only HTTP
        .authorizeHttpRequests((requests) -> requests
          .requestMatchers("/myAccount").hasRole("USER")
          .requestMatchers("/myBalance").hasAnyRole("USER", "ADMIN")
          .requestMatchers("/myLoans").hasRole("USER")
          .requestMatchers("/myCards").hasRole("USER")
          .requestMatchers("/user").authenticated()
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