package backup;


import java.io.*;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.*;
import com.security.springboot.demosecurity.DemosecurityApplication;
import com.squareup.javapoet.*;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.SignatureAlgorithm;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import javax.lang.model.element.Modifier;


public class endpointExtractionForJWT2{

    public static void main(String[] args) throws Exception {
        Properties properties = loadProperties("C:\\Users\\320241893\\Downloads\\demo (6)\\demo\\src\\test\\java\\com\\example\\demo\\securityPolicy.config");
        if (properties != null && "true".equals(properties.getProperty("checkDosPrevention"))) {
            List<String> urls = extractUrlsFromFile("C:\\Users\\320241893\\OneDrive - Philips\\Desktop\\demosecurity\\demosecurity\\src\\main\\java\\com\\security\\springboot\\demosecurity\\controller\\DemoController.java");
            if (!urls.isEmpty()) {
                for (String url : urls) {
                    System.out.println("URL: " + url);
                    generateTestExpiredJwtToken(url);
                }
            } else {
                System.out.println("No URLs found in the controller file.");
            }
        } else {
            System.out.println("Can't generate test case as security policy disabled for given test case");
        }
    }
    public static Properties loadProperties(String filePath) {
        Properties properties = new Properties();
        try (InputStream input = new FileInputStream(filePath)) {
            properties.load(input);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
        return properties;
    }

    public static List<String> extractUrlsFromFile(String filePath) throws Exception {
        List<String> urls = new ArrayList<>();
        FileInputStream fis = new FileInputStream(filePath);
        CompilationUnit cu = StaticJavaParser.parse(fis);
        for (MethodDeclaration method : cu.findAll(MethodDeclaration.class)) {
            for (AnnotationExpr annotation : method.getAnnotations()) {
                String url = extractUrlFromAnnotation(annotation);
                if (url != null) {
                    urls.add(url);
                }
            }
        }
        return urls;
    }

    private static String extractUrlFromAnnotation(AnnotationExpr annotation) {
        if (annotation instanceof SingleMemberAnnotationExpr) {
            SingleMemberAnnotationExpr singleAnnotation = (SingleMemberAnnotationExpr) annotation;
            return extractUrlFromAnnotationExpr(singleAnnotation);
        } else if (annotation instanceof NormalAnnotationExpr) {
            NormalAnnotationExpr normalAnnotation = (NormalAnnotationExpr) annotation;
            return extractUrlFromAnnotationExpr(normalAnnotation);
        }
        return null;
    }

    private static String extractUrlFromAnnotationExpr(AnnotationExpr annotation) {
        String annotationName = annotation.getNameAsString();
        if (annotationName.endsWith("Mapping")) {
            for (MemberValuePair pair : annotation.asNormalAnnotationExpr().getPairs()) {
                if (pair.getNameAsString().equals("value")) {
                    String value = pair.getValue().toString();
                    return value.replaceAll("\"", "");
                }
            }
        }
        return null;
    }
    private static void generateTestExpiredJwtToken(String url) {
        String methodName = "testExpiredJwtToken";

        // Add annotations
        AnnotationSpec autoConfigureMockMvcAnnotation = AnnotationSpec.builder(AutoConfigureMockMvc.class).build();
        AnnotationSpec springBootTestAnnotation = AnnotationSpec.builder(SpringBootTest.class)
                .addMember("classes", "$T.class", DemosecurityApplication.class)
                .build();
        AnnotationSpec withMockUserAnnotation = AnnotationSpec.builder(WithMockUser.class)
                .addMember("username", "$S", "ravi")
                .addMember("roles", "{$S}", "ADMIN")
                .build();

        // Add field
        FieldSpec mockMvcField = FieldSpec.builder(MockMvc.class, "mockMvc")
                .addModifiers(Modifier.PRIVATE)
                .addAnnotation(Autowired.class)
                .build();

        // Build method body
        MethodSpec createExpiredJwtTokenMethod = MethodSpec.methodBuilder("createExpiredJwtToken")
                .addModifiers(Modifier.PRIVATE)
                .returns(String.class)
                .addStatement("$T now = $T.now()", Instant.class, Instant.class)
                .addStatement("$T expirationTime = now.minus(36000, $T.SECONDS)", Instant.class, ChronoUnit.class)
                .addStatement("return $T.builder()\n" +
                        ".setSubject(\"ravi\")\n" +
                        ".setExpiration($T.from(expirationTime))\n" +
                        ".signWith($T.HS256, \"6bd24ba0c1485ccc121fc11c9f57959b953e2da8e21eda2d766a06fbf265d92\")\n" +
                        ".compact()", Jwts.class, Date.class, SignatureAlgorithm.class)
                .build();



        MethodSpec testMethod = MethodSpec.methodBuilder(methodName)
                .addModifiers(Modifier.PUBLIC)
                .addAnnotation(Test.class)
                .addAnnotation(withMockUserAnnotation)
                .addException(Exception.class)
                .returns(void.class)
                .addStatement("String expiredToken = createExpiredJwtToken()")
                .addStatement("mockMvc.perform($T.get($S).header(\"Authorization\", expiredToken))\n" +
                        ".andExpect($T.status().isOk())", MockMvcRequestBuilders.class, url, MockMvcResultMatchers.class)
                .build();

        // Build test class
        TypeSpec testClass = TypeSpec.classBuilder("TestExpiredJwtToken"+ capitalize(url.replace("/", "").replace("-", "").replace("{", "").replace("}", "")))
                .addModifiers(Modifier.PUBLIC)
                .addField(mockMvcField)
                .addMethod(createExpiredJwtTokenMethod)
                .addMethod(testMethod)
                .addAnnotation(autoConfigureMockMvcAnnotation)
                .addAnnotation(springBootTestAnnotation)
                .build();

        // Build Java file
        JavaFile javaFile = JavaFile.builder("com.example.tests", testClass)
                .addStaticImport(MockMvc.class, "perform")
                .addStaticImport(MockMvcRequestBuilders.class, "get") // Importing get method statically
                .addStaticImport(org.junit.jupiter.api.Test.class, "*")
                .addStaticImport(org.springframework.test.web.servlet.result.MockMvcResultMatchers.class, "*")
                .addStaticImport(org.springframework.security.test.context.support.WithMockUser.class, "*")
                .addStaticImport(SignatureAlgorithm.class, "*")
                .build();

        // Write to file
        File directory = new File("C:\\Users\\320241893\\OneDrive - Philips\\Desktop\\demosecurity\\demosecurity\\src\\test\\java\\newExample");
        directory.mkdirs();
        try {
            javaFile.writeTo(directory);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }



    private static String capitalize(String str) {
        if (str == null || str.isEmpty()) {
            return str;
        }
        return Character.toUpperCase(str.charAt(0)) + str.substring(1);
    }

}
