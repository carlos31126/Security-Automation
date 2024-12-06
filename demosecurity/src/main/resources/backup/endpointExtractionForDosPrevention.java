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
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import javax.lang.model.element.Modifier;


public class endpointExtractionForDosPrevention {

    public static void main(String[] args) throws Exception {
        Properties properties = loadProperties("C:\\Users\\320241893\\Downloads\\demo (6)\\demo\\src\\test\\java\\com\\example\\demo\\securityPolicy.config");
        if (properties != null && "true".equals(properties.getProperty("checkDosPrevention"))) {
            List<String> urls = extractUrlsFromFile("C:\\Users\\320241893\\OneDrive - Philips\\Desktop\\demosecurity\\demosecurity\\src\\main\\java\\com\\security\\springboot\\demosecurity\\controller\\DemoController.java");
            if (!urls.isEmpty()) {
                for (String url : urls) {
                    System.out.println("URL: " + url);
                    generateDOSPreventionTest(url);
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
    private static void generateDOSPreventionTest(String url) {
        MethodSpec dosPreventionMethod = MethodSpec.methodBuilder("testDOSPrevention")
                .addModifiers(Modifier.PUBLIC)
                .addException(Exception.class)
                .returns(void.class)
                .beginControlFlow("for (int i = 0; i < 100; i++)")
                .addStatement("mockMvc.perform(MockMvcRequestBuilders.get(\"" + url + "\"))\n" +
                        ".andExpect(status().is3xxRedirection())")
                .endControlFlow()
                .build();

        AnnotationSpec annotationSpec = AnnotationSpec.builder(Test.class).build();
        dosPreventionMethod = dosPreventionMethod.toBuilder().addAnnotation(annotationSpec).build();

        AnnotationSpec annAutowired = AnnotationSpec.builder(Autowired.class).build();

        TypeSpec testClass = TypeSpec.classBuilder("DOSPreventionTest" + capitalize(url.replace("/", "").replace("-","").replace("{", "").replace("}", "")))
                .addModifiers(Modifier.PUBLIC)
                .addAnnotation(AutoConfigureMockMvc.class)
                .addMethod(dosPreventionMethod)
                .addAnnotation(AnnotationSpec.builder(SpringBootTest.class).addMember("classes", "$T.class", DemosecurityApplication.class).build())
                .addField(FieldSpec.builder(MockMvc.class, "mockMvc")
                        .addModifiers(Modifier.PRIVATE)
                        .addAnnotation(annAutowired)
                        .build())
                .build();

        JavaFile javaFile = JavaFile.builder("com.example.demo", testClass)
                .addStaticImport(org.junit.jupiter.api.Test.class, "*")
                .addStaticImport(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.class, "*")
                .addStaticImport(org.springframework.test.web.servlet.result.MockMvcResultMatchers.class, "status")
                .build();

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
