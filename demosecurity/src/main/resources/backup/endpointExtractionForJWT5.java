package backup;


import java.io.*;
import java.security.Key;
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
import com.squareup.javapoet.*;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
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


public class endpointExtractionForJWT5{

    public static void main(String[] args) throws Exception {
        Properties properties = loadProperties("C:\\Users\\320241893\\Downloads\\demo (6)\\demo\\src\\test\\java\\com\\example\\demo\\securityPolicy.config");
        if (properties != null && "true".equals(properties.getProperty("checkDosPrevention"))) {
            List<String> urls = extractUrlsFromFile("C:\\Users\\320241893\\OneDrive - Philips\\Desktop\\demosecurity\\demosecurity\\src\\main\\java\\com\\security\\springboot\\demosecurity\\controller\\DemoController.java");
            if (!urls.isEmpty()) {
                for (String url : urls) {
                    System.out.println("URL: " + url);
                    generateTestTokenExpiration();
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
    private static void generateTestTokenExpiration() {
        String methodName = "testTokenExpiration";

        // Build method body
        MethodSpec testMethod = MethodSpec.methodBuilder(methodName)
                .addModifiers(Modifier.PUBLIC)
                .addAnnotation(Test.class)
                .returns(void.class)
                .addStatement("$T secretKey = $T.secretKeyFor($T.HS256)", Key.class, Keys.class, io.jsonwebtoken.SignatureAlgorithm.class)
                .addStatement("$T now = $T.now()", Instant.class, Instant.class)
                .addStatement("$T expirationTime = now.plus(20, $T.SECONDS)", Instant.class, ChronoUnit.class)
                .addStatement("String jwtToken = $T.builder()\n" +
                        ".setSubject(\"raj\")\n" +
                        ".setExpiration($T.from(expirationTime))\n" +
                        ".signWith(secretKey)\n" +
                        ".compact()", Jwts.class, Date.class)
                .addStatement("$T tokenExpiration = $T.parser()\n" +
                        ".setSigningKey(secretKey)\n" +
                        ".build()\n" +
                        ".parseClaimsJws(jwtToken)\n" +
                        ".getBody()\n" +
                        ".getExpiration()\n" +
                        ".toInstant()", Instant.class, Jwts.class)
                .addStatement("$T.assertTrue(now.isBefore(tokenExpiration), \"Token should be valid before expiration time\")", Assertions.class)
                .addStatement("$T.assertTrue(tokenExpiration.isBefore(expirationTime), \"Token should expire after the set expiration time\")", Assertions.class)
                .build();

        // Build Java file
        TypeSpec testClass = TypeSpec.classBuilder("TestTokenExpiration")
                .addModifiers(Modifier.PUBLIC)
                .addMethod(testMethod)
                .build();

        // Build Java file
        JavaFile javaFile = JavaFile.builder("com.example.tests", testClass)
                .addStaticImport(org.junit.jupiter.api.Test.class, "*")
                .addStaticImport(org.junit.jupiter.api.Assertions.class, "assertTrue")
                .addStaticImport(io.jsonwebtoken.security.Keys.class, "*")
                .addStaticImport(io.jsonwebtoken.Jwts.class, "*")
                .addStaticImport(java.time.Instant.class, "*")
                .addStaticImport(java.time.temporal.ChronoUnit.class, "*")
                .addStaticImport(java.util.Date.class, "*")
                .addStaticImport(java.security.Key.class, "*")
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
