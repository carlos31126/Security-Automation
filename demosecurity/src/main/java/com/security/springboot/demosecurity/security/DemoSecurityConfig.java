    package com.security.springboot.demosecurity.security;


    import io.jsonwebtoken.JwtBuilder;
    import io.jsonwebtoken.Jwts;

    import io.jsonwebtoken.SignatureAlgorithm;
    import io.jsonwebtoken.security.Keys;
    import jakarta.servlet.FilterChain;
    import jakarta.servlet.ServletException;
    import jakarta.servlet.http.Cookie;
    import jakarta.servlet.http.HttpServletRequest;
    import jakarta.servlet.http.HttpServletResponse;
    import org.hibernate.cfg.Environment;
    import org.springframework.beans.factory.annotation.Autowired;
    import org.springframework.beans.factory.annotation.Value;
    import org.springframework.context.annotation.Bean;
    import org.springframework.context.annotation.Configuration;
    import org.springframework.http.ResponseEntity;
    import org.springframework.security.config.Customizer;
    import org.springframework.security.config.annotation.web.builders.HttpSecurity;
    import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
    import org.springframework.security.core.Authentication;
    import org.springframework.security.core.GrantedAuthority;
    import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
    import org.springframework.security.core.context.SecurityContextHolder;
    import org.springframework.security.core.userdetails.User;
    import org.springframework.security.core.userdetails.UserDetails;

    import org.springframework.security.provisioning.InMemoryUserDetailsManager;
    import org.springframework.security.provisioning.JdbcUserDetailsManager;
    import org.springframework.security.provisioning.UserDetailsManager;
    import org.springframework.security.web.SecurityFilterChain;
    import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
    import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
    import org.springframework.security.web.csrf.*;
    import org.springframework.stereotype.Component;
    import org.springframework.web.filter.OncePerRequestFilter;


    import javax.crypto.SecretKey;
    import javax.sql.DataSource;
    import java.io.IOException;
    import java.nio.charset.StandardCharsets;
    import java.util.*;


    @Configuration
        public class DemoSecurityConfig {

            @Value("${jwt.secret}")
            String secretKey;

            @Autowired
            private JwtAuthenticationSuccessHandler jwtAuthenticationSuccessHandler;

            @Bean
            public UserDetailsManager userDetailsManager(DataSource dataSource){
                JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
                jdbcUserDetailsManager.setUsersByUsernameQuery("select user_id,pw,active from members where user_id=?");

                jdbcUserDetailsManager.setAuthoritiesByUsernameQuery(
                        "select user_id,role from roles where user_id=?"
                );
                return
                        jdbcUserDetailsManager;
            }
            @Bean
            public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
                http
                        .addFilterAfter(new JwtTokenFilter(), UsernamePasswordAuthenticationFilter.class)
                        .authorizeHttpRequests(configurer ->
                        configurer
                                .requestMatchers("/").hasRole("EMPLOYEE")
                                .requestMatchers("/leaders/**").hasRole("MANAGER")
                                .requestMatchers("/systems/**").hasRole("ADMIN")
                                .anyRequest().authenticated()
                )
                        .formLogin(form->
                                form
                                        .loginPage("/showMyLoginPage")
                                        .loginProcessingUrl("/authenticateTheUser")
                                        .permitAll()
                                        .successHandler(jwtAuthenticationSuccessHandler)

                        )
                        .logout(logout->logout.permitAll())
//                        .exceptionHandling(configurer->configurer.accessDeniedPage("/acess-denied"))
                        ;
                return http.build();
            }



        private class JwtTokenFilter extends OncePerRequestFilter {
            @Override
            protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
                    throws ServletException, IOException {
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                if (authentication != null && authentication.isAuthenticated()) {
                    String jwtToken = generateJwtToken(authentication);
                    response.setHeader("Authorization", jwtToken);
                }
                filterChain.doFilter(request, response);
            }
        }
        private Object generateTokenUponSuccess(HttpServletRequest request,
                                                HttpServletResponse response,
                                                Authentication authentication) throws IOException {

            String jwtToken = generateJwtToken(authentication); // Implement JWT generation logic
            response.setHeader("Authorization","Bearer"+jwtToken);
            return null;
        }

        public String generateJwtToken(Authentication authentication) {
            User user = (User) authentication.getPrincipal(); // Assuming User is your UserDetails implementation



            byte[] signingKey = secretKey.getBytes(StandardCharsets.UTF_8);

            return Jwts.builder()
                    .setSubject(user.getUsername())
                    .claim("authorities", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                    .setIssuedAt(new Date())
                    .setExpiration(new Date((new Date()).getTime() + 360000000)) // 1 hour expiration
                    .signWith(SignatureAlgorithm.HS256, signingKey)
                    .compact();
        }




        @Bean
        public static CsrfTokenRepository customCsrfTokenRepository() {
            return new HttpSessionCsrfTokenRepository();
        }

        @Bean
        public GrantedAuthoritiesMapper grantedAuthoritiesMapper() {
            return (authorities) -> authorities; // Or provide custom mapping logic if needed
        }

//
        private static class CsrfTokenGeneratorFilter extends OncePerRequestFilter {

            @Override
            protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
                    throws ServletException, IOException {
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                CsrfToken csrfToken = customCsrfTokenRepository().generateToken(request);
                request.setAttribute(CsrfToken.class.getName(), csrfToken);
                request.setAttribute(csrfToken.getParameterName(), csrfToken);
                filterChain.doFilter(request, response);
            }
        }

        private static class ShowFeedbacksFilter extends OncePerRequestFilter {
            @Override
            protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
                    throws ServletException, IOException {
                String requestURI = request.getRequestURI();
                if ("/show-feedbacks".equals(requestURI)) {

                    if (hasRequiredRole(request)) {
                        filterChain.doFilter(request, response);
                    } else {
                        response.sendRedirect("/access-denied");
                    }
                } else {
                    filterChain.doFilter(request, response);
                }
            }
            private boolean hasRequiredRole(HttpServletRequest request){
                return request.isUserInRole("MANAGER") || request.isUserInRole("ADMIN");
            }
        }















//        @Bean
//        public AuthenticationSuccessHandler jwtTokenGenerator(){
//                return new AuthenticationSuccessHandler() {
//                    @Override
//                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        String jwtToken = generateJwtToken(authentication);
//                        System.out.println("Generated JWT token: "+jwtToken);
//                        response.setHeader("Authorization",  jwtToken);
//
//                        response.sendRedirect("/");
//                    }
//                };
//        }













    }
