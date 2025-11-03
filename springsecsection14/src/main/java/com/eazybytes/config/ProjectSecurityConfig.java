package com.eazybytes.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class ProjectSecurityConfig {

  // create a bean of security filter chain
  @Bean
  SecurityFilterChain defaultSecurityFilterChain(HttpSecurity httpSecurity) throws Exception{
    httpSecurity.authorizeHttpRequests((request) -> request
        .requestMatchers("/secure").authenticated().anyRequest().permitAll())
        .formLogin(Customizer.withDefaults())
        .oauth2Login(Customizer.withDefaults());

    return httpSecurity.build();
  }

  /* provide the clue to the spring security framework on which
   authorization server to use (eg, own server or auth server
   */
  // create a bean of client registration repository to store all auth server details in the form of client registration
  @Bean
  ClientRegistrationRepository clientRegistrationRepository(){
    ClientRegistration github = githubClientRegistration();
    ClientRegistration facebook = facebookClientRegistration();
    return new InMemoryClientRegistrationRepository(github, facebook);
  }

  // create a private method that returns github client registration
  private ClientRegistration githubClientRegistration(){
    return CommonOAuth2Provider.GITHUB.getBuilder("github")
        .clientId("Ov23liAqxrSBtxFlsvX2")
        .clientSecret("cf34d5040b1fd1fdaca73627a4dc5b32447e46b1")
        .build();
  }

  // create a private method that returns facebook client registration
  private ClientRegistration facebookClientRegistration(){
    return CommonOAuth2Provider.FACEBOOK.getBuilder("facebook")
        .clientId("693615090375580")
        .clientSecret("9a9f09e11a3892af0c3abb8507f261d1")
        .build();
  }
}
