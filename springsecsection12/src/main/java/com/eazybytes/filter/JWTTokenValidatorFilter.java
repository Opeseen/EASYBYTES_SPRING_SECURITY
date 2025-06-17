package com.eazybytes.filter;

import com.eazybytes.constants.ApplicationConstants;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;

public class JWTTokenValidatorFilter extends OncePerRequestFilter {
  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
  String jwt = request.getHeader(ApplicationConstants.JWT_HEADER);
  LocalDateTime currentTimeStamp = LocalDateTime.now();
  String path = request.getRequestURI();
  if(jwt != null){
    try{
      Environment env = getEnvironment();
      String secret = env.getProperty(ApplicationConstants.JWT_SECRET, ApplicationConstants.JWT_SECRET_DEFAULT_VALUE);
      SecretKey secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
      Claims claims = Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(jwt).getPayload();
      String username = String.valueOf(claims.get("username"));
      String authorities = String.valueOf(claims.get("authorities"));
      Authentication authentication = new UsernamePasswordAuthenticationToken(username, null,
          AuthorityUtils.commaSeparatedStringToAuthorityList(authorities));
      SecurityContextHolder.getContext().setAuthentication(authentication);
    }catch (ExpiredJwtException exception){
      String jsonResponse = String.format("{\"timestamp\": \"%s\", \"code\": \"%d\", \"message\": \"%s\", \"path\": \"%s\"}",
          currentTimeStamp, HttpStatus.UNAUTHORIZED.value(), "Expired Token", path);
      response.setStatus(HttpStatus.UNAUTHORIZED.value());
      response.setContentType("application/json;charset=UTF-8");
      response.getWriter().write(jsonResponse);
      response.getWriter().flush();
    }catch(Exception exception){
      throw new BadCredentialsException("Invalid Token received");
    }
  }
    filterChain.doFilter(request, response);
  }
  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
    return request.getServletPath().equals("/user");
  }
}
