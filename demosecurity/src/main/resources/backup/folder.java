package backup;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.SingleMemberAnnotationExpr;
import com.squareup.javapoet.*;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.security.test.context.support.WithMockUser;

import javax.lang.model.element.Modifier;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class folder {
    public static void main(String[] args) throws Exception {
        String folderPath = "C:\\Users\\320241893\\OneDrive - Philips\\Desktop\\demosecurity\\demosecurity\\src";
        List<String> urls = extractUrlsFromFolder(folderPath);
        if (!urls.isEmpty()) {
            for (String url : urls) {
                System.out.println("URL: " + url);
                generateSecurityTestCases(url);
                generateCsrfTest(url);
            }
        } else {
            System.out.println("No URLs found in the controller files.");
        }
    }

    public static List<String> extractUrlsFromFolder(String folderPath) throws Exception {
        List<String> urls = new ArrayList<>();
        File folder = new File(folderPath);
        if (folder.exists() && folder.isDirectory()) {
            extractUrlsFromDirectory(folder, urls);
        }
        return urls;
    }

    private static void extractUrlsFromDirectory(File directory, List<String> urls) throws Exception {
        File[] files = directory.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isDirectory()) {
                    extractUrlsFromDirectory(file, urls);
                } else if (file.getName().endsWith(".java")) {
                    List<String> controllerUrls = extractUrlsFromController(file.getAbsolutePath());
                    urls.addAll(controllerUrls);
                }
            }
        }
    }

    public static List<String> extractUrlsFromController(String filePath) throws Exception {
        FileInputStream fis = new FileInputStream(filePath);
        CompilationUnit cu = StaticJavaParser.parse(fis);
        List<String> urls = new ArrayList<>();
        for (MethodDeclaration method : cu.findAll(MethodDeclaration.class)) {
            for (AnnotationExpr annotation : method.getAnnotations()) {
                if (annotation instanceof SingleMemberAnnotationExpr) {
                    String annotationName = annotation.getNameAsString();
                    if (annotationName.equals("GetMapping")) {
                        String url = extractUrlFromAnnotation(annotation.toString());
                        if (url != null) {
                            urls.add(url);
                        }
                    }
                }
            }
        }
        return urls;
    }

    private static String extractUrlFromAnnotation(String annotationString) {
        Pattern pattern = Pattern.compile("\\(\"(.*?)\"\\)");
        Matcher matcher = pattern.matcher(annotationString);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    private static void generateSecurityTestCases(String url) {
        MethodSpec csrfProtectionMethod = MethodSpec.methodBuilder("testCsrfProtection")
                .addModifiers(Modifier.PUBLIC)
                .addException(Exception.class)
                .returns(void.class)
                .addAnnotation(Test.class)
                .addStatement("MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders.get(\"" + url + "\"))" + "\n"
                        + ".andExpect(MockMvcResultMatchers.status().isFound())" + "\n"
                        + ".andReturn()")
                .addStatement("CsrfToken csrfToken = (CsrfToken) mvcResult.getRequest().getAttribute(CsrfToken.class.getName())",
                        CsrfToken.class, CsrfToken.class, CsrfToken.class)
                .addStatement("String csrfTokenValue = csrfToken.getToken()")
                .addStatement("mockMvc.perform(MockMvcRequestBuilders.post(\"http://localhost:8080/leaders\")" + "\n"
                        + ".param(\"username\", \"raj\")" + "\n"
                        + ".param(\"password\", \"fun123\")" + "\n"
                        + ".header(csrfToken.getHeaderName(), csrfTokenValue))" + "\n"
                        + ".andExpect(MockMvcResultMatchers.status().isForbidden())")
                .build();
        MethodSpec xssProtectionMethod = MethodSpec.methodBuilder("testXssProtection")
                .addModifiers(Modifier.PUBLIC)
                .addException(Exception.class)
                .returns(void.class)
                .addAnnotation(Test.class)
                .addStatement("String maliciousScript = \"<script>alert('XSS Attack');</script>\"")
                .addStatement("MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders.post(\"" + url + "\")" + "\n"
                        + ".contentType(MediaType.TEXT_HTML)" + "\n"
                        + ".content(maliciousScript))" + "\n"
                        + ".andExpect(MockMvcResultMatchers.status().isOk())" + "\n"
                        + ".andReturn()")
                .build();

        TypeSpec testClass = TypeSpec.classBuilder("SecurityTestFor" + capitalize(url.replace("/", "").replace("{", "").replace("}", "")))
                .addModifiers(Modifier.PUBLIC)
                .addAnnotation(AutoConfigureMockMvc.class)
                .addAnnotation(SpringBootTest.class)
                .addMethod(csrfProtectionMethod)
                .addField(FieldSpec.builder(MockMvc.class, "mockMvc")
                        .addModifiers(Modifier.PRIVATE)
                        .addAnnotation(Autowired.class)
                        .build())
                .build();


        JavaFile javaFile = JavaFile.builder("com.example.demo", testClass)
                .addStaticImport(Test.class, "*")
                .addStaticImport(MockMvcRequestBuilders.class, "*")
                .addStaticImport(MockMvcResultMatchers.class, "*")
                .addStaticImport(CsrfToken.class, "*")
                .build();

        File directory = new File("C:\\Users\\320241893\\OneDrive - Philips\\Desktop\\demosecurity\\demosecurity\\src\\test\\java\\com\\security\\springboot\\demosecurity\\onemore");
        directory.mkdirs();
        try {
            javaFile.writeTo(directory);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void generateCsrfTest(String url) {
        // Implementation for generating CSRF test cases
    }
    private static String capitalize(String str) {
        if (str == null || str.isEmpty()) {
            return str;
        }
        return Character.toUpperCase(str.charAt(0)) + str.substring(1);
    }
}
