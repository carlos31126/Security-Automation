package com.security.springboot.demosecurity.controller;


import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2ClientConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

    @GetMapping("/showMyLoginPage")
    public String showMyLoginPage( Model model){
        CsrfToken csrfToken = (CsrfToken) model.getAttribute(CsrfToken.class.getName());
        if (csrfToken != null) {
            String tokenValue = csrfToken.getToken();
            String parameterName = csrfToken.getParameterName();

            System.out.println("CSRF Token Value: " + tokenValue);
            System.out.println("CSRF Parameter Name: " + parameterName);
        }
        return "fancy-login";
    }

    @GetMapping("/access-denied")
    public String showAcessDenied(){
    return "access-denied";
    }


}


