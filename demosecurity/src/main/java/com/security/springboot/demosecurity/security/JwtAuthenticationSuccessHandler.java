package com.security.springboot.demosecurity.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final String secretKey;

    public JwtAuthenticationSuccessHandler(@Value("${jwt.secret}") String secretKey) {
        this.secretKey = secretKey;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        String jwtToken = generateJwtToken(authentication);
        response.setHeader("Authorization",  jwtToken);
        response.sendRedirect("/");
    }

    public String generateJwtToken(Authentication authentication) {
        User user = (User) authentication.getPrincipal();

        byte[] signingKey = secretKey.getBytes(StandardCharsets.UTF_8);

        return Jwts.builder()
                .setSubject(user.getUsername())
                .claim("authorities", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + 360000000)) // 1 hour expiration
                .signWith(SignatureAlgorithm.HS256, signingKey)
                .compact();
    }

}
