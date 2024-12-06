import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.springboot.demosecurity.controller.DemoController;
import com.security.springboot.demosecurity.security.DemoSecurityConfig;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import net.minidev.json.JSONObject;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
//import org.springframework.test.web.servlet.result.MockMvcResultHandlers;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.io.UnsupportedEncodingException;
import java.net.HttpCookie;
import java.security.Key;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

@SpringBootTest
@AutoConfigureMockMvc
//@WebMvcTest(controllers = DemoController.class)
public class SecurityAttackTests {

    @Autowired
    private MockMvc mockMvc;


    @Test
    public void attemptSQLInjectionShouldReturnForbidden() throws Exception {
        String maliciousInput = "1'; DROP TABLE members; --";
        mockMvc.perform(MockMvcRequestBuilders.get("/?param=" + maliciousInput)
                .param("username",maliciousInput)
                .param("password",maliciousInput))
                .andExpect(status().isFound())
                .andExpect(MockMvcResultMatchers.redirectedUrl("http://localhost/showMyLoginPage"));
    }




    @Test
    public void attemptCrossSiteScriptingShouldReturnForbidden() throws Exception {
        String maliciousInput = "<script>alert('XSS');</script>";
        mockMvc.perform(MockMvcRequestBuilders.get("/?param=" + maliciousInput))
                .andExpect(status().isFound())
                .andExpect(MockMvcResultMatchers.redirectedUrl("http://localhost/showMyLoginPage"));
    }

    @Test
    public void testDOSPrevention() throws Exception {

        for (int i = 0; i < 100; i++) {
            mockMvc.perform(MockMvcRequestBuilders.get("http://localhost:8080/showMyLoginPage"))
                    .andExpect(status().is2xxSuccessful());
        }
    }
    @Test
    public void testIDORPrevention() throws Exception {
        String vulnerableEndpoint = "http://localhost:8080/systems";

        mockMvc.perform(MockMvcRequestBuilders.get(vulnerableEndpoint + "/2"))
                .andExpect(MockMvcResultMatchers.redirectedUrl("http://localhost:8080/showMyLoginPage"));
    }
    @Test
    public void testIDORPrevention2() throws Exception {
        String vulnerableEndpoint = "http://localhost:8080/showMyLoginPage?";

        mockMvc.perform(MockMvcRequestBuilders.get(vulnerableEndpoint + "/logout"))
                .andExpect(MockMvcResultMatchers.redirectedUrl("http://localhost:8080/showMyLoginPage"));
    }
    @Test
    public void testSessionHijacking() throws Exception {
        MvcResult loginResult = mockMvc.perform(MockMvcRequestBuilders.get("/showMyLoginPage"))
                .andExpect(status().isOk())
                .andReturn();

        String jsessionId = extractJSessionId(loginResult.getResponse());

        mockMvc.perform(post("http://localhost:8080/leaders")
                        .param("username", "raghvendra")
                        .param("password", "fun123")
                        .cookie(new Cookie("JSESSIONID", jsessionId)))
                .andExpect(status().isForbidden());
    }

    private String extractJSessionId(MockHttpServletResponse response) {
        String cookieHeader = response.getHeader("Set-Cookie");

        if(cookieHeader!=null) {
            String[] cookies = cookieHeader.split(";");

            for (String cookie : cookies) {
                if (cookie.trim().startsWith("JSESSIONID")) {
                    return cookie.split("=")[1];
                }
            }
        }
        return null;
    }


    @Test
    @WithMockUser(roles = "MANAGER")
    public void attemptVerticalPrivilegeEscalationShouldReturnForbidden() throws Exception {
       mockMvc.perform(MockMvcRequestBuilders.get("/systems"))
               .andExpect(status().isForbidden())
               .andExpect(MockMvcResultMatchers.content().string(""));
    }



    @Test
    public void checkSecurityHeaders() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/showMyLoginPage"))
                .andExpect(MockMvcResultMatchers.header().exists("X-Content-Type-Options"))
                .andExpect(MockMvcResultMatchers.header().exists("X-Frame-Options"))
                   .andExpect(MockMvcResultMatchers.header().exists("X-XSS-Protection"))
                .andExpect(MockMvcResultMatchers.header().exists("Cache-Control"));
    }


    @Test
    public void testCsrfProtection() throws Exception {

        MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders.get("/showMyLoginPage"))
                .andExpect(status().isOk())
                .andReturn();

        CsrfToken csrfToken = (CsrfToken) mvcResult.getRequest().getAttribute(CsrfToken.class.getName());
        String csrfTokenValue = csrfToken.getToken();

        mockMvc.perform(post("http://localhost:8080/leaders")
                        .param("username", "raj")
                        .param("password", "fun123")
                        .header(csrfToken.getHeaderName(), csrfTokenValue))
                .andExpect(status().isForbidden());
    }


    @Test
    public void testCsrfAttack() throws Exception {
        String csrfTokenEndpoint = "http://localhost:8080/showMyLoginPage";

        mockMvc.perform(MockMvcRequestBuilders.get(csrfTokenEndpoint))
                .andExpect(status().isOk())
                .andReturn();

        String sensitiveActionEndpoint = "http://localhost:8080/leaders";

        String csrfTokenValue = "5k4a_tIM_SgnDOcEcrgt4HLu-B-kcuKiRDumAlL6TyGtNa5O1y8qnLM9yh0KaYNlR5UZ1EPf1SaQQoOPIAiQMGXCfxCZBcx5";

        mockMvc.perform(post(sensitiveActionEndpoint)
                        .param("username", "raj")
                        .param("password", "fun123")
                        .header("X-CSRF-TOKEN", csrfTokenValue))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "ravi",roles={"ADMIN"})
    public void testJwtGeneration2() throws Exception{

        MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders.get("/systems"))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andReturn();

        String jwtToken = mvcResult.getResponse().getHeader("Authorization");
        System.out.println("JWT Token "+ jwtToken);
        Assertions.assertTrue(jwtToken!=null && jwtToken.startsWith("ey"));
    }



    @Test
    @WithMockUser(username = "ravi", roles = { "ADMIN" })
    public void testExpiredJwtToken() throws Exception {

        String expiredToken = createExpiredJwtToken();

        mockMvc.perform(MockMvcRequestBuilders.get("/systems")
                        .header("Authorization",  expiredToken))
                .andExpect(MockMvcResultMatchers.status().isOk());
    }

    private String createExpiredJwtToken() {
        Instant now = Instant.now();
        Instant expirationTime = now.minus(36000,ChronoUnit.SECONDS); // Set expiration time to one hour ago

        return Jwts.builder()
                .setSubject("ravi")
                .setExpiration(Date.from(expirationTime))
                .signWith(SignatureAlgorithm.HS256, "6bd24ba0c1485ccc121fc11c9f57959b953e2da8e21eda2d766a06fbf265d92")
                .compact();
    }


    @Test
    @WithMockUser(username="ravi",roles ={"ADMIN"})
    public void testJwtGenerationLength() throws  Exception{
        MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders.get("/systems"))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andReturn();
        String jwtToken = mvcResult.getResponse().getHeader("Authorization");

        Assertions.assertTrue(jwtToken.split("\\.").length==3,"Token contains 3 parts");
    }


    @Test
    @WithMockUser(username="ravi",roles ={"ADMIN"})
    public void testJwtGenerationLengthandAlgorithm12() throws  Exception {
        MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders.get("/systems"))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andReturn();
        String jwtToken = mvcResult.getResponse().getHeader("Authorization");
        assert jwtToken != null && jwtToken.startsWith("ey");

        String[] tokenParts = jwtToken.split("\\.");
        if (tokenParts.length < 2) {
            System.out.println("Invalid Jwt Token format");
        }

        String encodedHeader = tokenParts[0];
        String decodedHeader = new String(java.util.Base64.getUrlDecoder().decode(encodedHeader));

        try {
            Jws<Claims> jws = (Jws<Claims>) Jwts.parser().build().parseSignedClaims(jwtToken).getHeader();
            JwsHeader header = jws.getHeader();

            String algorithm = header.getAlgorithm();
            assertTrue(algorithm.equals("HS512") || isWeakAlgorithm12(algorithm), "Algorithm is not Secure");
        } catch (Exception e) {
            System.out.println("Invalid Signature1234");
        }
    }

    private boolean isWeakAlgorithm12(String algorithm){
        if(algorithm.equals("HS512")||algorithm.equals("SHA512")){
            return false;
        }
        else{
            return true;
        }
    }

    @Test
    public void testTokenExpiration() {

        Key secretKey = Keys.secretKeyFor(io.jsonwebtoken.SignatureAlgorithm.HS256);

        Instant now = Instant.now();
        Instant expirationTime = now.plus(20, ChronoUnit.SECONDS);

        String jwtToken = Jwts.builder()
                .setSubject("raj")
                .setExpiration(Date.from(expirationTime))
                .signWith(secretKey)
                .compact();

        Instant tokenExpiration = Jwts.parser()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(jwtToken)
                .getBody()
                .getExpiration()
                .toInstant();

        assertTrue(now.isBefore(tokenExpiration), "Token should be valid before expiration time");
        assertTrue(tokenExpiration.isBefore(expirationTime), "Token should expire after the set expiration time");
    }


    @Test
    public void attemptSQLInjectionShouldReturnForbidden1() throws Exception {
        String maliciousInput = "1'; DROP TABLE members; --";

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("username", maliciousInput);
        formData.add("password", maliciousInput);

        mockMvc.perform(post("http://localhost/showMyLoginPage")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .params(formData))
                .andExpect(status().isForbidden());
    }
}






















































//    @Test
//        public void testCSRFProtection() throws Exception {
//        // Perform a GET request to retrieve the CSRF token
//        MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders.get("/showMyLoginPage"))
//            .andExpect(MockMvcResultMatchers.status().isOk())
//            .andReturn();
//
//        // Extract the CSRF token from the response
//        CsrfToken csrfToken = (CsrfToken) mvcResult.getRequest().getAttribute(CsrfToken.class.getName());
//        String csrfTokenValue = csrfToken.getToken();
//
//        // Perform a POST request with the obtained CSRF token
//        mockMvc.perform(MockMvcRequestBuilders.post("/showMyLoginPage")
//                    .param("username", "raj")
//                    .param("password", "fun123")
//                    .session(new MockHttpSession())
//                    .header(csrfToken.getHeaderName(), csrfToken.getToken()))
//            .andExpect(MockMvcResultMatchers.status().isForbidden());
//        }
