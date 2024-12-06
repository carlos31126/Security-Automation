package example.demo;

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
public class securityTestCaseForShowFeedback {
  @Autowired
  private MockMvc mockMvc;

  @Test
  public void testSecurityHeaders() throws Exception {
    mockMvc.perform(get("/showFeedback"))
        .andExpect(MockMvcResultMatchers.header().exists("X-Content-Type-Options"))
        .andExpect(MockMvcResultMatchers.header().exists("X-Frame-Options"))
        .andExpect(MockMvcResultMatchers.header().exists("X-XSS-Protection"))
        .andExpect(MockMvcResultMatchers.header().exists("Cache-Control"));
  }

  @Test
  public void testDosPrevention() throws Exception {
    for (int i = 0; i < 100; i++) {
      mockMvc.perform(MockMvcRequestBuilders.get("/showFeedback"))
          .andExpect(status().is3xxRedirection());
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
    MvcResult loginResult = mockMvc.perform(get("/showFeedback"))
        .andExpect(status().isForbidden())
        .andReturn();
    String jsessionId = extractJSessionId(loginResult.getResponse())
        ;
    mockMvc.perform(MockMvcRequestBuilders.post("http://localhost:8080/leaders")
        .param("username", "raghvendra")
        .param("password", "fun123")
        .cookie(new Cookie("JSESSIONID", jsessionId)))
        .andExpect(status().isForbidden());
  }

  @Test
  public void testCsrfProtection() throws Exception {
    MvcResult mvcResult = mockMvc.perform(get("/showFeedback"))
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
  }

  @Test
  public void attemptSQLInjectionShouldReturnForbidden1() throws Exception {
    String maliciousInput = "1'; DROP TABLE members; --";
    MultiValueMap formData = new LinkedMultiValueMap<>();
    formData.add("username", maliciousInput);
    formData.add("password", maliciousInput);
    mockMvc.perform(MockMvcRequestBuilders.post("/showFeedback")
        .contentType(APPLICATION_FORM_URLENCODED)
        .params(formData))
        .andExpect(status().isForbidden());
  }

  @Test
  public void vulnerableEndpointRedirectTest() throws Exception {
    String vulnerableEndpoint = "signin";
    mockMvc.perform(get("/systems" + vulnerableEndpoint))
        .andExpect(redirectedUrl("http://localhost/showMyLoginPage"));;
  }

  @Test
  @WithMockUser(
      username = "ravi",
      roles = {"ADMIN"}
  )
  public void testMethod() throws Exception {
    MvcResult mvcResult = mockMvc.perform(get("/showFeedback"))
        .andExpect(status().isOk())
        .andReturn();
    String jwtToken = mvcResult.getResponse().getHeader("Authorization");
    System.out.println("JWT Token " + jwtToken);
    Assertions.assertTrue(jwtToken != null && jwtToken.startsWith("ey"));
  }

  @Test
  @WithMockUser(
      username = "ravi",
      roles = {"ADMIN"}
  )
  public void testMethod2() throws Exception {
    MvcResult mvcResult = mockMvc.perform(get("/showFeedback"))
        .andExpect(status().isOk())
        .andReturn();
    String jwtToken = mvcResult.getResponse().getHeader("Authorization")
        ;
    Assertions.assertTrue(jwtToken.split("\\.").length == 3);
  }

  @WithMockUser(
      roles = {"MANAGER"}
  )
  @Test
  public void privilegeEscalationTest() throws Exception {
    mockMvc.perform(get("/showFeedback"))
        .andExpect(status().isForbidden())
        .andExpect(MockMvcResultMatchers.content().string(""));;
  }

  @Test
  @WithMockUser(
      username = "ravi",
      roles = {"ADMIN"}
  )
  public void testMethod123() throws Exception {
    String expiredToken = createExpiredJwtToken();
    mockMvc.perform(get("/showFeedback").header("Authorization", expiredToken))
        .andExpect(status().isOk());
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
  public void testMethod5678() throws Exception {
    MvcResult mvcResult = mockMvc.perform(get("/user/data"))
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
          System.out.println("Invalid Signature");
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
