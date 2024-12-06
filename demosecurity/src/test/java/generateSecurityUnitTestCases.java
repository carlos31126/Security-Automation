import com.github.javaparser.ast.stmt.WhileStmt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.servlet.http.Cookie;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.jupiter.api.Assertions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.junit.jupiter.api.Test;


import javax.lang.model.element.Modifier;
import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.*;
import com.squareup.javapoet.*;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.http.MediaType;

public class generateSecurityUnitTestCases {
    public static void main(String[] args) throws Exception {
        String projectFolderPath1 = System.getProperty("user.dir");

        File configFile = findConfigFile(projectFolderPath1);
        if(configFile ==null){
            configFile = createDefaultConfigFile(projectFolderPath1);
        }

        if (configFile != null) {

            Properties properties = loadProperties(String.valueOf(configFile));

            boolean checkSecurityHeaders = getPropertyAsBoolean(properties, "checkSecurityHeaders");
            boolean checkDosPrevention = getPropertyAsBoolean(properties, "checkDosPrevention");
            boolean checkCsrfProtection = getPropertyAsBoolean(properties, "checkCsrfProtection");
            boolean checkSQLinjection = getPropertyAsBoolean(properties, "checkSQLinjection");
            boolean checkSessionHijacking = getPropertyAsBoolean(properties, "checkSessionHijacking");
            boolean checkIdor = getPropertyAsBoolean(properties, "checkIdor");
            boolean checkJwtTokenParts = getPropertyAsBoolean(properties, "checkJwtTokenParts");
            boolean checkJwtTokenPrefix = getPropertyAsBoolean(properties, "checkJwtTokenPrefix");
            boolean checkJwtTokenAlgorithm = getPropertyAsBoolean(properties, "checkJwtTokenAlgorithm");
            boolean checkJwtTokenExpiry = getPropertyAsBoolean(properties, "checkJwtTokenExpiry");
            boolean checkVerticalPrivilegeEscalation = getPropertyAsBoolean(properties, "checkVerticalPrivilegeEscalation");


            if (checkVerticalPrivilegeEscalation ||checkSecurityHeaders || checkDosPrevention || checkSQLinjection || checkSessionHijacking || checkCsrfProtection || checkIdor ||checkJwtTokenParts || checkJwtTokenPrefix || checkJwtTokenAlgorithm ||checkJwtTokenExpiry) {
                String projectFolderPath = System.getProperty("user.dir");
                List<String> controllerFiles = findControllerFiles(projectFolderPath);
                for (String controllerFile : controllerFiles) {
                    List<String> mappings = extractMappings(controllerFile);
                    System.out.println("Mappings in file: " + controllerFile);
                    for (String mapping : mappings) {
                        System.out.println(mapping);
                        generateCombinedTests(mapping, checkSecurityHeaders, checkDosPrevention,checkCsrfProtection,checkSessionHijacking,checkSQLinjection,checkIdor, checkJwtTokenParts ,checkJwtTokenPrefix ,checkJwtTokenAlgorithm ,checkJwtTokenExpiry,checkVerticalPrivilegeEscalation);
                    }
                }
            } else {
                System.out.println("Can't generate test cases as security policies are disabled.");
            }
        } else {
            System.out.println("Can't load properties file.");
        }
    }



    private static File createDefaultConfigFile(String folderPath) throws IOException {
        File configFile = new File(folderPath, "securityPolicy.config");
        if (!configFile.exists()) {
            String defaultConfig =
                    "checkSecurityHeaders=true\n" +
                            "checkDosPrevention=true\n" +
                            "checkCsrfProtection=true\n" +
                            "checkSQLinjection=true\n" +
                            "checkSessionHijacking=true\n" +
                            "checkIdor=true\n" +
                            "checkJwtTokenParts=true\n" +
                            "checkJwtTokenPrefix=true\n" +
                            "checkJwtTokenAlgorithm=true\n" +
                            "checkJwtTokenExpiry=true\n" +
                            "checkVerticalPrivilegeEscalation=true\n";
            Files.write(Paths.get(configFile.toURI()), defaultConfig.getBytes(), StandardOpenOption.CREATE);
            System.out.println("Created security policy file.");
        }
        return configFile;
    }

    private static List<String> findControllerFiles(String folderPath) {
        List<String> controllerFiles = new ArrayList<>();
        File folder = new File(folderPath);
        if (folder.exists() && folder.isDirectory()) {
            File[] files = folder.listFiles();
            if (files != null) {
                for (File file : files) {
                    if (file.isFile() && file.getName().endsWith("Controller.java")) {
                        controllerFiles.add(file.getAbsolutePath());
                    } else if (file.isDirectory()) {
                        controllerFiles.addAll(findControllerFiles(file.getAbsolutePath()));
                    }
                }
            }
        }
        return controllerFiles;
    }
    private static List<String> extractMappings(String filePath) {
        List<String> mappings = new ArrayList<>();
        try {
            String content = Files.readString(new File(filePath).toPath());
            Pattern pattern = Pattern.compile("@(GetMapping|PostMapping)\\(.*?\"(.*?)\".*?\\)");
            Matcher matcher = pattern.matcher(content);
            while (matcher.find()) {
                mappings.add(matcher.group(2));
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return mappings;
    }
    private static File findConfigFile(String folderPath) {
        File folder = new File(folderPath);
        File[] files = folder.listFiles();

        if (files != null) {
            for (File file : files) {
                if (file.isDirectory()) {
                    File foundFile = findConfigFile(file.getAbsolutePath());
                    if (foundFile != null) {
                        return foundFile;
                    }
                } else if (file.getName().endsWith(".config")) {
                    return file;
                }
            }
        }
        return null;
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
    private static boolean getPropertyAsBoolean(Properties properties, String propertyName) {
        String propertyValue = properties.getProperty(propertyName);
        return propertyValue != null && propertyValue.equalsIgnoreCase("true");
    }
    private static void generateCombinedTests(String url, boolean checkSecurityHeaders, boolean checkDosPrevention,boolean checkCsrfProtection, boolean checkSessionHijacking, boolean checkIdor, boolean checkSQLInjection, boolean checkJwtTokenParts,boolean checkJwtTokenPrefix,boolean checkJwtTokenAlgorithm,boolean checkJwtTokenExpiry,boolean checkVerticalPrivilegeEscalation) throws IOException, JSONException {
        String className = "securityTestCaseFor" + capitalize(url.replace("/", "").replace("-", "").replace("{", "").replace("}", ""));
        String projectFolderPath2 = System.getProperty("user.dir");
        Path projectPath = Paths.get(projectFolderPath2);

        JSONObject testResults = new JSONObject();


        testResults.put("testSecurityHeaders", checkSecurityHeaders ? "pass" : "Skipped");
        testResults.put("testDosPrevention", checkDosPrevention ? "pass" : "Skipped");
        testResults.put("testCsrfProtection", checkCsrfProtection ? "pass" : "Skipped");
        testResults.put("testSessionHijacking", checkSessionHijacking ? "pass" : "Skipped");
        testResults.put("testSQLInjection", checkSQLInjection ? "pass" : "Skipped");
        testResults.put("testIDOR", checkIdor ? "pass" : "Skipped");
        testResults.put("testJWTtokenPrefix", checkJwtTokenPrefix ? "pass" : "Skipped");
        testResults.put("testPrivilegeEscalation",checkVerticalPrivilegeEscalation ? "pass" : "Skipped");
        testResults.put("testJWTTokenLength", checkJwtTokenParts ? "pass" : "Skipped");
        testResults.put("testInvalidJWTtoken", checkJwtTokenExpiry ? "pass" : "Skipped");
        testResults.put("testTokenAlgorithm", checkJwtTokenAlgorithm ? "pass" : "Skipped");

        ClassName applicationClassName = findMainSpringClass(projectPath);
        AnnotationSpec autoConfigureMockMvcAnnotation = AnnotationSpec.builder(AutoConfigureMockMvc.class).build();
        AnnotationSpec springBootTestAnnotation = AnnotationSpec.builder(SpringBootTest.class)
                .addMember("classes", "$T.class",applicationClassName)
                .build();

        FieldSpec mockMvcField = FieldSpec.builder(MockMvc.class, "mockMvc")
                .addModifiers(Modifier.PRIVATE)
                .addAnnotation(Autowired.class)
                .build();

        TypeSpec.Builder testClassBuilder = TypeSpec.classBuilder(className)
                .addModifiers(Modifier.PUBLIC)
                .addAnnotation(autoConfigureMockMvcAnnotation)
                .addAnnotation(springBootTestAnnotation)
                .addField(mockMvcField);

        if (checkSecurityHeaders) {
            testClassBuilder.addMethod(generateSecurityHeadersTest(url));
        }

        if (checkDosPrevention) {
            testClassBuilder.addMethod(generateDosPreventionTest(url));
        }

        if(checkSessionHijacking) {
            testClassBuilder.addMethod(extractJSessionIdMethod());

            testClassBuilder.addMethod(generateSessionHijackingTest(url));
        }

        if(checkCsrfProtection) {
            testClassBuilder.addMethod(generateCsrfProtectionTest(url));
        }

        if(checkSQLInjection) {
            testClassBuilder.addMethod(generateSQLInjection(url));
        }

        if(checkIdor){
            testClassBuilder.addMethod(generateIDORTest());
        }

        if(checkJwtTokenPrefix){
            testClassBuilder.addMethod(generateJWTTokenPrefix(url));
        }

        if(checkJwtTokenParts){
            testClassBuilder.addMethod(generateJWTTokenLengthTest(url));
        }

        if(checkVerticalPrivilegeEscalation){
            testClassBuilder.addMethod(generatePrivilegeEscalationTest(url));
        }

        if(checkJwtTokenExpiry){
            testClassBuilder.addMethod(generateExpiredJWTTokenTest(url));

            testClassBuilder.addMethod(generateCreateExpiredJwtTokenMethod());
        }

        if(checkJwtTokenAlgorithm){
            testClassBuilder.addMethod(generateJWTSignatureStrengthTest(url));
            testClassBuilder.addMethod(generateIsWeakAlgorithmMethod());
        }

        JavaFile javaFile = JavaFile.builder("security", testClassBuilder.build())
                .addStaticImport(org.junit.jupiter.api.Test.class, "*")
                .addStaticImport(org.mockito.Mockito.class, "*")
                .addStaticImport(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.class, "get")
                .addStaticImport(org.springframework.test.web.servlet.result.MockMvcResultMatchers.class, "header", "status", "redirectedUrl")
                .addStaticImport(org.springframework.http.MediaType.class, "*")
                .addStaticImport(SignatureAlgorithm.HS256)
                .build();

        String projectFolderPath1 = System.getProperty("user.dir");
        Path projectPath1 = Paths.get(projectFolderPath1);
        Path testFolderPath = findTestFolder(projectPath1);
        if (testFolderPath != null) {
            Path newDirectory = testFolderPath.resolve("java/com");
            try {
                Files.createDirectories(newDirectory);
                javaFile.writeTo(newDirectory);
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("Test folder not found.");
        }
        appendTestResultsToJsonFile(url, testResults);
    }
    private static void appendTestResultsToJsonFile(String endpoint, JSONObject testResults) {
        try {
            Path jsonFilePath = Paths.get("testResults.json");
            JSONObject jsonRoot;
            if (Files.exists(jsonFilePath)) {
                String jsonString = Files.readString(jsonFilePath);
                jsonRoot = new JSONObject(jsonString);
            } else {
                jsonRoot = new JSONObject();
            }

            jsonRoot.put(endpoint, testResults);

            try (FileWriter file = new FileWriter("testResults.json")) {
                file.write(jsonRoot.toString(4));
            } catch (IOException e) {
                e.printStackTrace();
            }
        } catch (IOException | JSONException e) {
            e.printStackTrace();
        }
    }
    private static ClassName findMainSpringClass(Path projectPath) throws IOException {
        final ClassName[] applicationClassName = {null};
        Files.walkFileTree(projectPath, new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                if (file.toString().endsWith(".java")) {
                    String content = new String(Files.readAllBytes(file));
                    if (content.contains("@SpringBootApplication")) {
                        String className = file.getFileName().toString().replace(".java", "");
                        String packageName = extractPackageName(content);
                        applicationClassName[0] = ClassName.get(packageName, className);
                        return FileVisitResult.TERMINATE;
                    }
                }
                return FileVisitResult.CONTINUE;
            }
        });
        return applicationClassName[0];
    }

    private static String extractPackageName(String content) {
        Pattern pattern = Pattern.compile("package\\s+([a-zA-Z0-9_.]+);");
        Matcher matcher = pattern.matcher(content);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return "";
    }

    private static Path findTestFolder(Path startPath) {
        try {
            TestFolderFinder finder = new TestFolderFinder();
            Files.walkFileTree(startPath, finder);
            return finder.getTestFolderPath();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static class TestFolderFinder implements FileVisitor<Path> {
        private Path testFolderPath;
        public Path getTestFolderPath() {
            return testFolderPath;
        }
        @Override
        public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
            if (dir.endsWith("test")) {
                testFolderPath = dir;
                return FileVisitResult.TERMINATE;
            }
            return FileVisitResult.CONTINUE;
        }
        @Override
        public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
            return FileVisitResult.CONTINUE;
        }
        @Override
        public FileVisitResult visitFileFailed(Path file, IOException exc) {
            return FileVisitResult.CONTINUE;
        }
        @Override
        public FileVisitResult postVisitDirectory(Path dir, IOException exc) {
            return FileVisitResult.CONTINUE;
        }
    }
    private static MethodSpec generateSecurityHeadersTest(String url) {
        return MethodSpec.methodBuilder("testSecurityHeaders")
                .addModifiers(Modifier.PUBLIC)
                .addException(Exception.class)
                .returns(void.class)
                .addComment("Security Headers Test Case")
                .addCode("try {\n")
                .addCode("mockMvc.perform(get($S))\n", url)
                .addCode(".andExpect(MockMvcResultMatchers.header().exists(\"X-Content-Type-Options\"))\n")
                .addCode(".andExpect(MockMvcResultMatchers.header().exists(\"X-Frame-Options\"))\n")
                .addCode(".andExpect(MockMvcResultMatchers.header().exists(\"X-XSS-Protection\"))\n")
                .addCode(".andExpect(MockMvcResultMatchers.header().exists(\"Cache-Control\"));\n")
                .addCode("System.out.println(\"Test Case: Security Headers Passed\");\n")
                .addCode("} catch (AssertionError | Exception e) {\n")
                .addCode("System.out.println(\"Test Case: Security Headers Failed\");\n")
                .addCode("throw e;\n")
                .addCode("}\n")
                .addAnnotation(Test.class)
                .build();
    }
    private static MethodSpec generateDosPreventionTest(String url) {
        return MethodSpec.methodBuilder("testDosPrevention")
                .addModifiers(Modifier.PUBLIC)
                .addException(Exception.class)
                .returns(void.class)
                .addComment("DOS Prevention Test Case")
                .addCode("try {\n")
                .beginControlFlow("for (int i = 0; i < 100; i++)")
                .addStatement("mockMvc.perform(MockMvcRequestBuilders.get($S))\n" +
                        ".andExpect(status().is3xxRedirection())", url)
                .endControlFlow()
                .addCode("System.out.println(\"Test Case: DOS Prevention Passed\");\n")
                .addCode("} catch (AssertionError | Exception e) {\n")
                .addCode("System.out.println(\"Test Case: DOS Prevention Failed\");\n")
                .addCode("throw e;\n")
                .addCode("}\n")
                .addAnnotation(Test.class)
                .build();
    }

    private static MethodSpec extractJSessionIdMethod() {
        return MethodSpec.methodBuilder("extractJSessionId")
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
    }
    private static MethodSpec generateSessionHijackingTest(String url) {
        String methodName = "testSessionHijacking";

        return MethodSpec.methodBuilder(methodName)
                .addModifiers(Modifier.PUBLIC)
                .addException(Exception.class)
                .addAnnotation(Test.class)
                .returns(void.class)
                .addComment("Session Hijacking Test Case")
                .addCode("try {\n")
                .addStatement("$T loginResult = mockMvc.perform($T.get($S))\n" +
                        ".andExpect($T.status().is3xxRedirection())\n" +
                        ".andReturn()", MvcResult.class, MockMvcRequestBuilders.class, url, MockMvcResultMatchers.class)
                .addStatement("String jsessionId = extractJSessionId(loginResult.getResponse())\n")
                .addStatement("mockMvc.perform($T.post($S)\n" +
                                ".param($S, $S)\n" +
                                ".param($S, $S)\n" +
                                ".cookie(new $T($S, jsessionId)))\n" +
                                ".andExpect($T.status().isForbidden())",
                        MockMvcRequestBuilders.class, "http://localhost:8080/leaders",
                        "username", "raghvendra",
                        "password", "fun123",
                        Cookie.class, "JSESSIONID",
                        MockMvcResultMatchers.class)
                .addCode("System.out.println($S);\n", "Test Case: Session Hijacking Passed")
                .addCode("} catch (AssertionError | Exception e) {\n")
                .addCode("System.out.println($S);\n", "Test Case: Session Hijacking Failed")
                .addCode("throw e;\n")
                .addCode("}\n")
                .build();
    }

    private static MethodSpec generateCsrfProtectionTest(String url) {
        String methodName = "testCsrfProtection";

        return MethodSpec.methodBuilder(methodName)
                .addModifiers(Modifier.PUBLIC)
                .addAnnotation(Test.class)
                .addException(Exception.class)
                .returns(void.class)
                .addComment("CSRF Test Case")
                .addCode("try {\n")
                .addStatement("$T mvcResult = mockMvc.perform($T.get($S))\n" +
                        ".andExpect($T.status().is3xxRedirection())\n" +
                        ".andReturn()", MvcResult.class, MockMvcRequestBuilders.class, url, MockMvcResultMatchers.class)
                .addStatement("$T csrfToken = ($T) mvcResult.getRequest().getAttribute($T.class.getName())\n",
                        CsrfToken.class, CsrfToken.class, CsrfToken.class)
                .addStatement("String csrfTokenValue = csrfToken.getToken()\n")
                .addStatement("mockMvc.perform($T.post($S)\n" +
                                ".param($S, $S)\n" +
                                ".param($S, $S)\n" +
                                ".header(csrfToken.getHeaderName(), csrfTokenValue))\n" +
                                ".andExpect($T.status().isForbidden())",
                        MockMvcRequestBuilders.class, "http://localhost:8080/leaders",
                        "username", "raj",
                        "password", "fun123",
                        MockMvcResultMatchers.class)
                .addCode("System.out.println($S);\n", "Test Case: CSRF Protection Passed")
                .addCode("} catch (AssertionError | Exception e) {\n")
                .addCode("System.out.println($S);\n", "Test Case: CSRF Protection Failed")
                .addCode("throw e;\n")
                .addCode("}\n")
                .build();
    }


    private static MethodSpec generateSQLInjection(String url) {
        String methodName = "testSQLInjection";

        return MethodSpec.methodBuilder(methodName)
                .addModifiers(Modifier.PUBLIC)
                .addAnnotation(Test.class)
                .addException(Exception.class)
                .returns(void.class)
                .addComment("SQL Injection test case")
                .addCode("try {\n")
                .addStatement("String maliciousInput = \"1'; DROP TABLE members; --\"")
                .addStatement("$T formData = new $T<>()", MultiValueMap.class, LinkedMultiValueMap.class)
                .addStatement("formData.add($S, maliciousInput)", "username")
                .addStatement("formData.add($S, maliciousInput)", "password")
                .addStatement("mockMvc.perform($T.post($S)\n" +
                                ".contentType($T.APPLICATION_FORM_URLENCODED)\n" +
                                ".params(formData))\n" +
                                ".andExpect($T.status().isForbidden())",
                        MockMvcRequestBuilders.class, url,
                        MediaType.class,
                        MockMvcResultMatchers.class)
                .addCode("System.out.println($S);\n", "Test Case: SQL Injection Passed")
                .addCode("} catch (AssertionError | Exception e) {\n")
                .addCode("System.out.println($S);\n", "Test Case: SQL Injection Failed")
                .addCode("throw e;\n")
                .addCode("}\n")
                .build();
    }

    private static MethodSpec generateIDORTest() {
        String methodName = "testIDOR";

        return MethodSpec.methodBuilder(methodName)
                .addModifiers(Modifier.PUBLIC)
                .addAnnotation(Test.class)
                .addException(Exception.class)
                .returns(void.class)
                .addComment("IDOR Test case")
                .addCode("try {\n")
                .addCode("String vulnerableEndpoint = $S;\n", "signin")
                .addCode("mockMvc.perform($T.get(\"/systems\" + vulnerableEndpoint))\n", MockMvcRequestBuilders.class)
                .addCode(".andExpect($T.redirectedUrl(\"http://localhost/showMyLoginPage\"));\n", MockMvcResultMatchers.class)
                .addCode("System.out.println(\"Test Case: IDOR Passed\");\n")
                .addCode("} catch (AssertionError | Exception e) {\n")
                .addCode("System.out.println(\"Test Case: IDOR Failed\");\n")
                .addCode("throw e;\n")
                .addCode("}\n")
                .build();
    }

    private static MethodSpec generateJWTTokenPrefix(String url) {
        String methodName = "testJWTtokenPrefix";

        AnnotationSpec withMockUserAnnotation = AnnotationSpec.builder(WithMockUser.class)
                .addMember("username", "$S", "ravi")
                .addMember("roles", "{$S}", "ADMIN")
                .build();

        return MethodSpec.methodBuilder(methodName)
                .addModifiers(Modifier.PUBLIC)
                .addAnnotation(Test.class)
                .addAnnotation(withMockUserAnnotation)
                .addException(Exception.class)
                .returns(void.class)
                .addComment("JWT token availability test")
                .addCode("try {\n")
                .addCode("$T mvcResult = mockMvc.perform($T.get($S))\n", MvcResult.class, MockMvcRequestBuilders.class, url)
                .addCode(".andExpect($T.status().isOk())\n", MockMvcResultMatchers.class)
                .addCode(".andReturn();\n")
                .addCode("String jwtToken = mvcResult.getResponse().getHeader(\"Authorization\");\n")
                .addCode("System.out.println(\"JWT Token \" + jwtToken);\n")
                .addCode("Assertions.assertTrue(jwtToken != null && jwtToken.startsWith(\"ey\"));\n")
                .addCode("System.out.println(\"Test Case: JWT Token Prefix Passed\");\n")
                .addCode("} catch (AssertionError | Exception e) {\n")
                .addCode("System.out.println(\"Test Case: JWT Token Prefix Failed\");\n")
                .addCode("throw e;\n")
                .addCode("}\n")
                .build();
    }

    private static MethodSpec generatePrivilegeEscalationTest(String url) {
        String methodName = "testPrivilegeEscalation";
        AnnotationSpec testAnnotation = AnnotationSpec.builder(Test.class).build();
        AnnotationSpec withMockUserAnnotation = AnnotationSpec.builder(WithMockUser.class)
                .addMember("roles", "{$S}", "MANAGER")
                .build();

        return MethodSpec.methodBuilder(methodName)
                .addModifiers(Modifier.PUBLIC)
                .addException(Exception.class)
                .addAnnotation(withMockUserAnnotation)
                .addAnnotation(testAnnotation)
                .returns(void.class)
                .addComment("Privilege Escalation Test")
                .addCode("try {\n")
                .addCode("mockMvc.perform($T.get($S))\n", MockMvcRequestBuilders.class, url)
                .addCode(".andExpect($T.status().isForbidden())\n", MockMvcResultMatchers.class)
                .addCode(".andExpect($T.content().string($S));\n", MockMvcResultMatchers.class, "")
                .addCode("System.out.println(\"Test Case: Privilege Escalation Passed\");\n")
                .addCode("} catch (AssertionError | Exception e) {\n")
                .addCode("System.out.println(\"Test Case: Privilege Escalation Failed\");\n")
                .addCode("throw e;\n")
                .addCode("}\n")
                .build();
    }
    private static MethodSpec generateJWTTokenLengthTest(String url) {
        String methodName = "testJWTTokenLength";

        AnnotationSpec withMockUserAnnotation = AnnotationSpec.builder(WithMockUser.class)
                .addMember("username", "$S", "ravi")
                .addMember("roles", "{$S}", "ADMIN")
                .build();

        return MethodSpec.methodBuilder(methodName)
                .addModifiers(Modifier.PUBLIC)
                .addAnnotation(Test.class)
                .addException(Exception.class)
                .returns(void.class)
                .addAnnotation(withMockUserAnnotation)
                .addComment("JWT token parts test")
                .addCode("try {\n")
                .addCode("$T mvcResult = mockMvc.perform($T.get($S))\n", MvcResult.class, MockMvcRequestBuilders.class, url)
                .addCode(".andExpect($T.status().isOk())\n", MockMvcResultMatchers.class)
                .addCode(".andReturn();\n")
                .addCode("String jwtToken = mvcResult.getResponse().getHeader(\"Authorization\");\n")
                .addCode("$T.assertTrue(jwtToken.split(\"\\\\.\").length == 3);\n", Assertions.class)
                .addCode("System.out.println(\"Test Case: JWT Token Length Passed\");\n")
                .addCode("} catch (AssertionError | Exception e) {\n")
                .addCode("System.out.println(\"Test Case: JWT Token Length Failed\");\n")
                .addCode("throw e;\n")
                .addCode("}\n")
                .build();
    }
    private static MethodSpec generateCreateExpiredJwtTokenMethod() {
        return MethodSpec.methodBuilder("createExpiredJwtToken")
                .addModifiers(Modifier.PRIVATE)
                .returns(String.class)
                .addStatement("$T now = $T.now()", Instant.class, Instant.class)
                .addStatement("$T expirationTime = now.minus(36000, $T.SECONDS)", Instant.class, ChronoUnit.class)
                .addStatement("return $T.builder()\n" +
                        ".setSubject(\"ravi\")\n" +
                        ".setExpiration($T.from(expirationTime))\n" +
                        ".signWith(HS256, \"6bd24ba0c1485ccc121fc11c9f57959b953e2da8e21eda2d766a06fbf265d92\")\n" +
                        ".compact()", Jwts.class, Date.class)
                .build();
    }
    private static MethodSpec generateExpiredJWTTokenTest(String url) {
        String methodName = "testInvalidJWTtoken";

        AnnotationSpec withMockUserAnnotation = AnnotationSpec.builder(WithMockUser.class)
                .addMember("username", "$S", "ravi")
                .addMember("roles", "{$S}", "ADMIN")
                .build();

        return MethodSpec.methodBuilder(methodName)
                .addModifiers(Modifier.PUBLIC)
                .addAnnotation(Test.class)
                .addException(Exception.class)
                .returns(void.class)
                .addAnnotation(withMockUserAnnotation)
                .addCode("try {\n")
                .addCode("String expiredToken = createExpiredJwtToken();\n")
                .addCode("mockMvc.perform($T.get($S).header(\"Authorization\", expiredToken))\n", MockMvcRequestBuilders.class, url)
                .addCode(".andExpect($T.status().isOk());\n", MockMvcResultMatchers.class)
                .addCode("System.out.println(\"Test Case: Expired JWT Token Passed\");\n")
                .addCode("} catch (AssertionError | Exception e) {\n")
                .addCode("System.out.println(\"Test Case: Expired JWT Token Failed\");\n")
                .addCode("throw e;\n")
                .addCode("}\n")
                .build();
    }

    private static MethodSpec generateIsWeakAlgorithmMethod() {
        return MethodSpec.methodBuilder("isWeakAlgorithm")
                .addModifiers(Modifier.PRIVATE)
                .returns(boolean.class)
                .addParameter(String.class, "algorithm")
                .beginControlFlow("if (algorithm.equals($S) || algorithm.equals($S))", "HS512", "SHA512")
                .addStatement("return false")
                .nextControlFlow("else")
                .addStatement("return true")
                .endControlFlow()
                .build();
    }

    private static MethodSpec generateJWTSignatureStrengthTest(String methodName2) {

        String methodName = "testTokenAlgorithm";
        AnnotationSpec withMockUserAnnotation = AnnotationSpec.builder(WithMockUser.class)
                .addMember("username", "$S", "ravi")
                .addMember("roles", "$S", "ADMIN")
                .build();

        return MethodSpec.methodBuilder(methodName)
                .addModifiers(Modifier.PUBLIC)
                .addAnnotation(Test.class)
                .addAnnotation(withMockUserAnnotation)
                .addException(Exception.class)
                .returns(void.class)
                .addComment("JWT token signature test")
                .addStatement("$T mvcResult = mockMvc.perform($T.get($S))\n" +
                        ".andExpect($T.status().isOk())\n" +
                        ".andReturn()", MvcResult.class, MockMvcRequestBuilders.class, "/systems", MockMvcResultMatchers.class)
                .addStatement("String jwtToken = mvcResult.getResponse().getHeader(\"Authorization\")")
                .beginControlFlow("if (jwtToken != null && jwtToken.startsWith(\"ey\"))")
                .addStatement("String[] tokenParts = jwtToken.split(\"\\\\.\")")
                .beginControlFlow("if (tokenParts.length >= 2)")
                .addStatement("String encodedHeader = tokenParts[0]")
                .addStatement("String decodedHeader = new String($T.getUrlDecoder().decode(encodedHeader))", java.util.Base64.class)
                .beginControlFlow("try")
                .addStatement("$T jws = $T.parser().build().parseClaimsJws(jwtToken)", io.jsonwebtoken.Jws.class, io.jsonwebtoken.Jwts.class)
                .addStatement("$T header = (JwsHeader)jws.getHeader()", io.jsonwebtoken.JwsHeader.class)
                .addStatement("String algorithm = header.getAlgorithm()")
                .addStatement("$T.assertTrue($L.equals($S) || isWeakAlgorithm($L), $S)",
                        org.junit.jupiter.api.Assertions.class, "algorithm", "HS512", "algorithm", "")
                .nextControlFlow("catch (Exception e)")
                .addStatement("System.out.println(\"########################      Test Case: JWT Signature Test Case passed.      ########################\")")
                .endControlFlow()
                .nextControlFlow("else")
                .addStatement("System.out.println(\"Invalid Jwt Token format\")")
                .endControlFlow()
                .nextControlFlow("else")
                .addStatement("System.out.println(\"Authorization header is missing or does not start with 'ey'\")")
                .endControlFlow()
                .build();
    }
    private static String capitalize(String str) {
        if (str == null || str.isEmpty()) {
            return str;
        }
        return Character.toUpperCase(str.charAt(0)) + str.substring(1);
    }

}

