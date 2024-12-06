package backup;


import java.io.*;
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
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import javax.lang.model.element.Modifier;


public class endpointExtractionForSessionHijacking {

    public static void main(String[] args) throws Exception {
        Properties properties = loadProperties("C:\\Users\\320241893\\Downloads\\demo (6)\\demo\\src\\test\\java\\com\\example\\demo\\securityPolicy.config");
        if (properties != null && "true".equals(properties.getProperty("checkDosPrevention"))) {
            List<String> urls = extractUrlsFromFile("C:\\Users\\320241893\\OneDrive - Philips\\Desktop\\demosecurity\\demosecurity\\src\\main\\java\\com\\security\\springboot\\demosecurity\\controller\\DemoController.java");
            if (!urls.isEmpty()) {
                for (String url : urls) {
                    System.out.println("URL: " + url);
                    generateTestSessionHijacking(url);
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
    private static void generateTestSessionHijacking(String url) {
        String methodName = "testSessionHijacking";

        AnnotationSpec autoConfigureMockMvcAnnotation = AnnotationSpec.builder(AutoConfigureMockMvc.class).build();
        AnnotationSpec springBootTestAnnotation = AnnotationSpec.builder(SpringBootTest.class)
                .addMember("classes", "$T.class", DemosecurityApplication.class)
                .build();

        // Add field
        FieldSpec mockMvcField = FieldSpec.builder(MockMvc.class, "mockMvc")
                .addModifiers(Modifier.PRIVATE)
                .addAnnotation(Autowired.class)
                .build();

        // Build method body
        MethodSpec testMethod = MethodSpec.methodBuilder(methodName)
                .addModifiers(Modifier.PUBLIC)
                .addException(Exception.class)
                .addAnnotation(Test.class)
                .returns(void.class)
                .addStatement("$T loginResult = mockMvc.perform($T.get(\"" + url + "\"))\n" +
                        ".andExpect($T.status().isForbidden())\n" +
                        ".andReturn()", MvcResult.class, MockMvcRequestBuilders.class, MockMvcResultMatchers.class)
                .addStatement("String jsessionId = extractJSessionId(loginResult.getResponse())\n")
                .addStatement("mockMvc.perform($T.post(\"http://localhost:8080/leaders\")\n" +
                        ".param(\"username\", \"raghvendra\")\n" +
                        ".param(\"password\", \"fun123\")\n" +
                        ".cookie(new $T(\"JSESSIONID\", jsessionId)))\n" +
                        ".andExpect($T.status().isForbidden())", MockMvcRequestBuilders.class, Cookie.class, MockMvcResultMatchers.class)
                .build();

        // Build helper method to extract JSESSIONID
        MethodSpec extractJSessionIdMethod = MethodSpec.methodBuilder("extractJSessionId")
                .addModifiers(Modifier.PRIVATE)
                .returns(String.class)
                .addParameter(MockHttpServletResponse.class, "response")
                .addStatement("String cookieHeader = response.getHeader(\"Set-Cookie\")")
                .beginControlFlow("if (cookieHeader != null)")
                .addStatement("$T[] cookies = cookieHeader.split(\";\")", String.class)
                .beginControlFlow("for ($T cookie : cookies)", String.class)
                .beginControlFlow("if (cookie.trim().startsWith(\"JSESSIONID\"))")
                .addStatement("return cookie.split(\"=\")[1]")
                .endControlFlow()
                .endControlFlow()
                .endControlFlow()
                .addStatement("return null")
                .build();

        // Build test class
        TypeSpec testClass = TypeSpec.classBuilder("TestSessionHijacking"+ capitalize(url.replace("/", "").replace("-","").replace("{", "").replace("}", "")))
                .addModifiers(Modifier.PUBLIC)
                .addField(mockMvcField)
                .addMethod(testMethod)
                .addMethod(extractJSessionIdMethod)
                .addAnnotation(autoConfigureMockMvcAnnotation)
                .addAnnotation(springBootTestAnnotation)
                .build();

        // Build Java file
        JavaFile javaFile = JavaFile.builder("com.example.tests", testClass)
                .addStaticImport(org.junit.jupiter.api.Test.class, "*")
                .addStaticImport(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.class, "*")
                .addStaticImport(org.springframework.test.web.servlet.result.MockMvcResultMatchers.class, "*")
                .addStaticImport(org.springframework.test.web.servlet.result.MockMvcResultMatchers.class, "*")
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