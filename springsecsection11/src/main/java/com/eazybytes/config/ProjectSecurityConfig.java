package com.eazybytes.config;

import com.eazybytes.exceptionHandling.CustomAccessDeniedHandler;
import com.eazybytes.exceptionHandling.CustomBasicAuthenticationEntryPoint;
import com.eazybytes.filter.*;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@Profile("!prod")
public class ProjectSecurityConfig {
  @Bean
  SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    CsrfTokenRequestAttributeHandler csrfTokenRequestAttributeHandler = new CsrfTokenRequestAttributeHandler();
    http
        .sessionManagement(sessionConfig ->
            sessionConfig.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) //create a session to be used to access resources
        .cors(cors -> cors.configurationSource(new CorsConfigFilter()))
        .csrf(csrfConfig -> csrfConfig.csrfTokenRequestHandler(csrfTokenRequestAttributeHandler)
            .ignoringRequestMatchers( "/contact","/register", "/apiLogin")
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
        .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
        .addFilterAfter(new AuthoritiesLoggingAfterFilter(),BasicAuthenticationFilter.class)
        .addFilterAfter(new JWTTokenGeneratorFilter(), BasicAuthenticationFilter.class)
        .addFilterBefore(new JWTTokenValidatorFilter(), BasicAuthenticationFilter.class)
        .addFilterBefore(new RequestValidationBeforeFilter(), BasicAuthenticationFilter.class)
        .requiresChannel(rcc -> rcc.anyRequest().requiresInsecure()) // Only HTTP
        .authorizeHttpRequests((requests) -> requests
          .requestMatchers("/myAccount").hasRole("USER")
          .requestMatchers("/myBalance").hasAnyRole("USER", "ADMIN")
          .requestMatchers("/myLoans").hasRole("USER")
          .requestMatchers("/myCards").hasRole("USER")
          .requestMatchers("/user").authenticated()
          .requestMatchers("notices","/contact","/error", "/register", "/invalidSession", "/apiLogin").permitAll()
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
  @Bean
  public CompromisedPasswordChecker compromisedPasswordChecker(){
    return new HaveIBeenPwnedRestApiPasswordChecker();
  }

  @Bean
  public AuthenticationManager authenticationManager(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder){
    EazyBankUsernamePwdAuthenticationProvider authenticationProvider =
        new EazyBankUsernamePwdAuthenticationProvider(userDetailsService, passwordEncoder);
    ProviderManager providerManager = new ProviderManager(authenticationProvider);
    providerManager.setEraseCredentialsAfterAuthentication(false);
    return providerManager;
  }
}