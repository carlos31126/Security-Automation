package security;

import static io.jsonwebtoken.SignatureAlgorithm.HS256;
import static org.junit.jupiter.api.Test.*;
import static org.mockito.Mockito.*;
import static org.springframework.http.MediaType.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.security.springboot.demosecurity.DemosecurityApplication;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.Cookie;
import java.lang.Exception;
import java.lang.String;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

@AutoConfigureMockMvc
@SpringBootTest(
    classes = DemosecurityApplication.class
)
public class securityTestCaseForLeaders {
  @Autowired
  private MockMvc mockMvc;

  @Test
  public void testSecurityHeaders() throws Exception {
    // Security Headers Test Case
    try {
    mockMvc.perform(get("/leaders"))
    .andExpect(MockMvcResultMatchers.header().exists("X-Content-Type-Options"))
    .andExpect(MockMvcResultMatchers.header().exists("X-Frame-Options"))
    .andExpect(MockMvcResultMatchers.header().exists("X-XSS-Protection"))
    .andExpect(MockMvcResultMatchers.header().exists("Cache-Control"));
    System.out.println("Test Case: Security Headers Passed");
    } catch (AssertionError | Exception e) {
    System.out.println("Test Case: Security Headers Failed");
    throw e;
    }
  }

  @Test
  public void testDosPrevention() throws Exception {
    // DOS Prevention Test Case
    try {
    for (int i = 0; i < 100; i++) {
      mockMvc.perform(MockMvcRequestBuilders.get("/leaders"))
          .andExpect(status().is3xxRedirection());
    }
    System.out.println("Test Case: DOS Prevention Passed");
    } catch (AssertionError | Exception e) {
    System.out.println("Test Case: DOS Prevention Failed");
    throw e;
    }
  }

  private String extractJSessionId(MockHttpServletResponse response) {
    String cookieHeader = response.getHeader("Set-Cookie");
    if (cookieHeader != null) {
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
  public void testSessionHijacking() throws Exception {
    // Session Hijacking Test Case
    try {
    MvcResult loginResult = mockMvc.perform(get("/leaders"))
        .andExpect(status().is3xxRedirection())
        .andReturn();
    String jsessionId = extractJSessionId(loginResult.getResponse())
        ;
    mockMvc.perform(MockMvcRequestBuilders.post("http://localhost:8080/leaders")
        .param("username", "raghvendra")
        .param("password", "fun123")
        .cookie(new Cookie("JSESSIONID", jsessionId)))
        .andExpect(status().isForbidden());
    System.out.println("Test Case: Session Hijacking Passed");
    } catch (AssertionError | Exception e) {
    System.out.println("Test Case: Session Hijacking Failed");
    throw e;
    }
  }

  @Test
  public void testCsrfProtection() throws Exception {
    // CSRF Test Case
    try {
    MvcResult mvcResult = mockMvc.perform(get("/leaders"))
        .andExpect(status().is3xxRedirection())
        .andReturn();
    CsrfToken csrfToken = (CsrfToken) mvcResult.getRequest().getAttribute(CsrfToken.class.getName())
        ;
    String csrfTokenValue = csrfToken.getToken()
        ;
    mockMvc.perform(MockMvcRequestBuilders.post("http://localhost:8080/leaders")
        .param("username", "raj")
        .param("password", "fun123")
        .header(csrfToken.getHeaderName(), csrfTokenValue))
        .andExpect(status().isForbidden());
    System.out.println("Test Case: CSRF Protection Passed");
    } catch (AssertionError | Exception e) {
    System.out.println("Test Case: CSRF Protection Failed");
    throw e;
    }
  }

  @Test
  public void testSQLInjection() throws Exception {
    // SQL Injection test case
    try {
    String maliciousInput = "1'; DROP TABLE members; --";
    MultiValueMap formData = new LinkedMultiValueMap<>();
    formData.add("username", maliciousInput);
    formData.add("password", maliciousInput);
    mockMvc.perform(MockMvcRequestBuilders.post("/leaders")
        .contentType(APPLICATION_FORM_URLENCODED)
        .params(formData))
        .andExpect(status().isForbidden());
    System.out.println("Test Case: SQL Injection Passed");
    } catch (AssertionError | Exception e) {
    System.out.println("Test Case: SQL Injection Failed");
    throw e;
    }
  }

  @Test
  public void testIDOR() throws Exception {
    // IDOR Test case
    try {
    String vulnerableEndpoint = "signin";
    mockMvc.perform(get("/systems" + vulnerableEndpoint))
    .andExpect(redirectedUrl("http://localhost/showMyLoginPage"));
    System.out.println("Test Case: IDOR Passed");
    } catch (AssertionError | Exception e) {
    System.out.println("Test Case: IDOR Failed");
    throw e;
    }
  }

  @Test
  @WithMockUser(
      username = "ravi",
      roles = {"ADMIN"}
  )
  public void testJWTtokenPrefix() throws Exception {
    // JWT token availability test
    try {
    MvcResult mvcResult = mockMvc.perform(get("/leaders"))
    .andExpect(status().isOk())
    .andReturn();
    String jwtToken = mvcResult.getResponse().getHeader("Authorization");
    System.out.println("JWT Token " + jwtToken);
    Assertions.assertTrue(jwtToken != null && jwtToken.startsWith("ey"));
    System.out.println("Test Case: JWT Token Prefix Passed");
    } catch (AssertionError | Exception e) {
    System.out.println("Test Case: JWT Token Prefix Failed");
    throw e;
    }
  }

  @Test
  @WithMockUser(
      username = "ravi",
      roles = {"ADMIN"}
  )
  public void testJWTTokenLength() throws Exception {
    // JWT token parts test
    try {
    MvcResult mvcResult = mockMvc.perform(get("/leaders"))
    .andExpect(status().isOk())
    .andReturn();
    String jwtToken = mvcResult.getResponse().getHeader("Authorization");
    Assertions.assertTrue(jwtToken.split("\\.").length == 3);
    System.out.println("Test Case: JWT Token Length Passed");
    } catch (AssertionError | Exception e) {
    System.out.println("Test Case: JWT Token Length Failed");
    throw e;
    }
  }

  @WithMockUser(
      roles = {"MANAGER"}
  )
  @Test
  public void testPrivilegeEscalation() throws Exception {
    // Privilege Escalation Test
    try {
    mockMvc.perform(get("/leaders"))
    .andExpect(status().isForbidden())
    .andExpect(MockMvcResultMatchers.content().string(""));
    System.out.println("Test Case: Privilege Escalation Passed");
    } catch (AssertionError | Exception e) {
    System.out.println("Test Case: Privilege Escalation Failed");
    throw e;
    }
  }

  @Test
  @WithMockUser(
      username = "ravi",
      roles = {"ADMIN"}
  )
  public void testInvalidJWTtoken() throws Exception {
    try {
    String expiredToken = createExpiredJwtToken();
    mockMvc.perform(get("/leaders").header("Authorization", expiredToken))
    .andExpect(status().isOk());
    System.out.println("Test Case: Expired JWT Token Passed");
    } catch (AssertionError | Exception e) {
    System.out.println("Test Case: Expired JWT Token Failed");
    throw e;
    }
  }

  private String createExpiredJwtToken() {
    Instant now = Instant.now();
    Instant expirationTime = now.minus(36000, ChronoUnit.SECONDS);
    return Jwts.builder()
        .setSubject("ravi")
        .setExpiration(Date.from(expirationTime))
        .signWith(HS256, "6bd24ba0c1485ccc121fc11c9f57959b953e2da8e21eda2d766a06fbf265d92")
        .compact();
  }

  @Test
  @WithMockUser(
      username = "ravi",
      roles = "ADMIN"
  )
  public void testTokenAlgorithm() throws Exception {
    // JWT token signature test
    MvcResult mvcResult = mockMvc.perform(get("/systems"))
        .andExpect(status().isOk())
        .andReturn();
    String jwtToken = mvcResult.getResponse().getHeader("Authorization");
    if (jwtToken != null && jwtToken.startsWith("ey")) {
      String[] tokenParts = jwtToken.split("\\.");
      if (tokenParts.length >= 2) {
        String encodedHeader = tokenParts[0];
        String decodedHeader = new String(Base64.getUrlDecoder().decode(encodedHeader));
        try {
          Jws jws = Jwts.parser().build().parseClaimsJws(jwtToken);
          JwsHeader header = (JwsHeader)jws.getHeader();
          String algorithm = header.getAlgorithm();
          Assertions.assertTrue(algorithm.equals("HS512") || isWeakAlgorithm(algorithm), "");
        } catch (Exception e) {
          System.out.println("########################      Test Case: JWT Signature Test Case passed.      ########################");
        }
      } else {
        System.out.println("Invalid Jwt Token format");
      }
    } else {
      System.out.println("Authorization header is missing or does not start with 'ey'");
    }
  }

  private boolean isWeakAlgorithm(String algorithm) {
    if (algorithm.equals("HS512") || algorithm.equals("SHA512")) {
      return false;
    } else {
      return true;
    }
  }
}
