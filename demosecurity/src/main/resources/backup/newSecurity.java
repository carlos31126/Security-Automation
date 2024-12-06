package backup;

import com.security.springboot.demosecurity.controller.LoginController;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import javax.swing.*;

@RunWith(SpringRunner.class)
@WebMvcTest(LoginController.class)
public class newSecurity {
    @Autowired
    private MockMvc mockMvc;

    @Test
    public void testCSRFProtection() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/showMyLoginPage"))
                .andExpect(MockMvcResultMatchers.status().isOk());

        mockMvc.perform(MockMvcRequestBuilders.post("/showMyLoginPage")
                        .param("username", "raj")
                        .param("password", "fun123")
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(MockMvcResultMatchers.status().isOk());
    }
}
