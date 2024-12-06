package backup;

public class backUpCode {
    //    public static void main(String[] args) throws Exception {
//        String projectFolderPath1 = System.getProperty("user.dir");
//
//        File configFile = findConfigFile(projectFolderPath1);
//        if (configFile != null) {
//
//            Properties properties = loadProperties(String.valueOf(configFile));
//            boolean checkSecurityHeaders = getPropertyAsBoolean(properties, "checkSecurityHeaders");
//            boolean checkDosPrevention = getPropertyAsBoolean(properties, "checkDosPrevention");
//            boolean checkCsrfProtection = getPropertyAsBoolean(properties, "checkCsrfProtection");
//            boolean checkSQLinjection = getPropertyAsBoolean(properties, "checkSQLinjection");
//            boolean checkSessionHijacking = getPropertyAsBoolean(properties, "checkSessionHijacking");
//            boolean checkIdor = getPropertyAsBoolean(properties, "checkIdor");
//            boolean checkJwtTokenParts = getPropertyAsBoolean(properties, "checkJwtTokenParts");
//            boolean checkJwtTokenPrefix = getPropertyAsBoolean(properties, "checkJwtTokenPrefix");
//            boolean checkJwtTokenAlgorithm = getPropertyAsBoolean(properties, "checkJwtTokenAlgorithm");
//            boolean checkJwtTokenExpiry = getPropertyAsBoolean(properties, "checkJwtTokenExpiry");
//            boolean checkVerticalPrivilegeEscalation = getPropertyAsBoolean(properties, "checkVerticalPrivilegeEscalation");
//
//            if (checkVerticalPrivilegeEscalation ||checkSecurityHeaders || checkDosPrevention || checkSQLinjection || checkSessionHijacking || checkCsrfProtection || checkIdor ||checkJwtTokenParts || checkJwtTokenPrefix || checkJwtTokenAlgorithm ||checkJwtTokenExpiry) {
//                String projectFolderPath = System.getProperty("user.dir");
//                List<String> controllerFiles = findControllerFiles(projectFolderPath);
//                for (String controllerFile : controllerFiles) {
//                    List<String> mappings = extractMappings(controllerFile);
//                    System.out.println("Mappings in file: " + controllerFile);
//                    for (String mapping : mappings) {
//                        System.out.println(mapping);
//                        generateCombinedTests(mapping, checkSecurityHeaders, checkDosPrevention,checkCsrfProtection,checkSessionHijacking,checkSQLinjection,checkIdor, checkJwtTokenParts ,checkJwtTokenPrefix ,checkJwtTokenAlgorithm ,checkJwtTokenExpiry,checkVerticalPrivilegeEscalation);
//                    }
//                }
//            } else {
//                System.out.println("Can't generate test cases as security policies are disabled.");
//            }
//        } else {
//            System.out.println("Can't load properties file.");
//        }
//    }
//    private static List<String> findControllerFiles(String folderPath) {
//        List<String> controllerFiles = new ArrayList<>();
//        File folder = new File(folderPath);
//        if (folder.exists() && folder.isDirectory()) {
//            File[] files = folder.listFiles();
//            if (files != null) {
//                for (File file : files) {
//                    if (file.isFile() && file.getName().endsWith("Controller.java")) {
//                        controllerFiles.add(file.getAbsolutePath());
//                    } else if (file.isDirectory()) {
//                        controllerFiles.addAll(findControllerFiles(file.getAbsolutePath()));
//                    }
//                }
//            }
//        }
//        return controllerFiles;
//    }
//
//    private static List<String> extractMappings(String filePath) {
//        List<String> mappings = new ArrayList<>();
//        try {
//            String content = Files.readString(new File(filePath).toPath());
//            Pattern pattern = Pattern.compile("@(GetMapping|PostMapping)\\(.*?\"(.*?)\".*?\\)");
//            Matcher matcher = pattern.matcher(content);
//            while (matcher.find()) {
//                mappings.add(matcher.group(2));
//            }
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//        return mappings;
//    }
//    private static File findConfigFile(String folderPath) {
//        File folder = new File(folderPath);
//        File[] files = folder.listFiles();
//
//        if (files != null) {
//            for (File file : files) {
//                if (file.isDirectory()) {
//                    File foundFile = findConfigFile(file.getAbsolutePath());
//                    if (foundFile != null) {
//                        return foundFile;
//                    }
//                } else if (file.getName().endsWith(".config")) {
//                    return file;
//                }
//            }
//        }
//        return null;
//    }
//
//    public static Properties loadProperties(String filePath) {
//        Properties properties = new Properties();
//        try (InputStream input = new FileInputStream(filePath)) {
//            properties.load(input);
//        } catch (IOException e) {
//            e.printStackTrace();
//            return null;
//        }
//        return properties;
//    }
//    private static boolean getPropertyAsBoolean(Properties properties, String propertyName) {
//        String propertyValue = properties.getProperty(propertyName);
//        return propertyValue != null && propertyValue.equalsIgnoreCase("true");
//    }
//    private static void generateCombinedTests(String url, boolean checkSecurityHeaders, boolean checkDosPrevention,boolean checkCsrfProtection, boolean checkSessionHijacking, boolean checkIdor, boolean checkSQLInjection, boolean checkJwtTokenParts,boolean checkJwtTokenPrefix,boolean checkJwtTokenAlgorithm,boolean checkJwtTokenExpiry,boolean checkVerticalPrivilegeEscalation) {
//        String className = "CombinedTestFor" + capitalize(url.replace("/", "").replace("-", "").replace("{", "").replace("}", ""));
//
//        AnnotationSpec autoConfigureMockMvcAnnotation = AnnotationSpec.builder(AutoConfigureMockMvc.class).build();
//        AnnotationSpec springBootTestAnnotation = AnnotationSpec.builder(SpringBootTest.class)
//                .addMember("classes", "$T.class", DemosecurityApplication.class)
//                .build();
//
//        FieldSpec mockMvcField = FieldSpec.builder(MockMvc.class, "mockMvc")
//                .addModifiers(Modifier.PRIVATE)
//                .addAnnotation(Autowired.class)
//                .build();
//
//        TypeSpec.Builder testClassBuilder = TypeSpec.classBuilder(className)
//                .addModifiers(Modifier.PUBLIC)
//                .addAnnotation(autoConfigureMockMvcAnnotation)
//                .addAnnotation(springBootTestAnnotation)
//                .addField(mockMvcField);
//
//        if (checkSecurityHeaders) {
//            testClassBuilder.addMethod(generateSecurityHeadersTest(url));
//        }
//
//        if (checkDosPrevention) {
//            testClassBuilder.addMethod(generateDosPreventionTest(url));
//        }
//
//        if(checkSessionHijacking) {
//            testClassBuilder.addMethod(extractJSessionIdMethod());
//
//            testClassBuilder.addMethod(generateSessionHijackingTest(url));
//        }
//
//
//        if(checkCsrfProtection) {
//            testClassBuilder.addMethod(generateCsrfProtectionTest(url));
//        }
//
//
//        if(checkSQLInjection) {
//            testClassBuilder.addMethod(attemptSQLInjectionShouldReturnForbidden1(url));
//        }
//
//        if(checkIdor){
//            testClassBuilder.addMethod(vulnerableEndpointRedirectTest());
//        }
//
//        if(checkJwtTokenPrefix){
//            testClassBuilder.addMethod(generateTestMethod(url));
//        }
//
//        if(checkJwtTokenParts){
//            testClassBuilder.addMethod(generateTestMethod2(url));
//        }
//
//        if(checkVerticalPrivilegeEscalation){
//            testClassBuilder.addMethod(generateTestMethod12344(url));
//        }
//
//        if(checkJwtTokenExpiry){
//            testClassBuilder.addMethod(generateTestMethod12(url));
//
//            testClassBuilder.addMethod(generateCreateExpiredJwtTokenMethod());
//        }
//
//        if(checkJwtTokenAlgorithm){
//            testClassBuilder.addMethod(generateTestMethod1234(url));
//            testClassBuilder.addMethod(generateIsWeakAlgorithmMethod());
//        }
//
//        JavaFile javaFile = JavaFile.builder("com.example.demo", testClassBuilder.build())
//                .addStaticImport(org.junit.jupiter.api.Test.class, "*")
//                .addStaticImport(org.mockito.Mockito.class, "*")
//                .addStaticImport(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.class, "*")
//                .addStaticImport(org.springframework.test.web.servlet.result.MockMvcResultMatchers.class, "header", "status", "redirectedUrl")
//                .addStaticImport(org.springframework.http.MediaType.class, "*")
//                .addStaticImport(io.jsonwebtoken.Jwts.class,"*")
//                .addStaticImport(io.jsonwebtoken.Claims.class,"*")
//                .addStaticImport(org.junit.jupiter.api.Assertions.class,"*")
//                .addStaticImport(io.jsonwebtoken.Jws.class,"*")
//                .addStaticImport(io.jsonwebtoken.JwsHeader.class,"*")
//                .build();
//
//        File directory = new File("C:\\Users\\320241893\\OneDrive - Philips\\Desktop\\demosecurity\\demosecurity\\src\\test\\java\\newExample");
//        directory.mkdirs();
//        try {
//            javaFile.writeTo(directory);
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//    }
//    private static MethodSpec generateSecurityHeadersTest(String url) {
//        return MethodSpec.methodBuilder("testSecurityHeaders")
//                .addModifiers(Modifier.PUBLIC)
//                .addException(Exception.class)
//                .returns(void.class)
//                .addStatement("mockMvc.perform(get(\"" + url + "\"))" + "\n"
//                        + ".andExpect(MockMvcResultMatchers.header().exists(\"X-Content-Type-Options\"))" + "\n"
//                        + ".andExpect(MockMvcResultMatchers.header().exists(\"X-Frame-Options\"))" + "\n"
//                        + ".andExpect(MockMvcResultMatchers.header().exists(\"X-XSS-Protection\"))" + "\n"
//                        + ".andExpect(MockMvcResultMatchers.header().exists(\"Cache-Control\"))")
//                .addAnnotation(Test.class)
//                .build();
//    }
//
//    private static MethodSpec generateDosPreventionTest(String url) {
//        return MethodSpec.methodBuilder("testDosPrevention")
//                .addModifiers(Modifier.PUBLIC)
//                .addException(Exception.class)
//                .returns(void.class)
//                .beginControlFlow("for (int i = 0; i < 100; i++)")
//                .addStatement("mockMvc.perform(MockMvcRequestBuilders.get(\"" + url + "\"))\n" +
//                        ".andExpect(status().is3xxRedirection())")
//                .endControlFlow()
//                .addAnnotation(Test.class)
//                .build();
//    }
//
//    private static MethodSpec extractJSessionIdMethod() {
//        return MethodSpec.methodBuilder("extractJSessionId")
//                .addModifiers(Modifier.PRIVATE)
//                .returns(String.class)
//                .addParameter(MockHttpServletResponse.class, "response")
//                .addStatement("String cookieHeader = response.getHeader(\"Set-Cookie\")")
//                .beginControlFlow("if (cookieHeader != null)")
//                .addStatement("$T[] cookies = cookieHeader.split(\";\")", String.class)
//                .beginControlFlow("for ($T cookie : cookies)", String.class)
//                .beginControlFlow("if (cookie.trim().startsWith(\"JSESSIONID\"))")
//                .addStatement("return cookie.split(\"=\")[1]")
//                .endControlFlow()
//                .endControlFlow()
//                .endControlFlow()
//                .addStatement("return null")
//                .build();
//    }
//
//    private static MethodSpec generateSessionHijackingTest(String url) {
//        String methodName = "testSessionHijacking";
//
//        return MethodSpec.methodBuilder(methodName)
//                .addModifiers(Modifier.PUBLIC)
//                .addException(Exception.class)
//                .addAnnotation(Test.class)
//                .returns(void.class)
//                .addStatement("$T loginResult = mockMvc.perform($T.get(\"" + url + "\"))\n" +
//                        ".andExpect($T.status().isForbidden())\n" +
//                        ".andReturn()", MvcResult.class, MockMvcRequestBuilders.class, MockMvcResultMatchers.class)
//                .addStatement("String jsessionId = extractJSessionId(loginResult.getResponse())\n")
//                .addStatement("mockMvc.perform($T.post(\"http://localhost:8080/leaders\")\n" +
//                        ".param(\"username\", \"raghvendra\")\n" +
//                        ".param(\"password\", \"fun123\")\n" +
//                        ".cookie(new $T(\"JSESSIONID\", jsessionId)))\n" +
//                        ".andExpect($T.status().isForbidden())", MockMvcRequestBuilders.class, Cookie.class, MockMvcResultMatchers.class)
//                .build();
//    }
//    private static MethodSpec generateCsrfProtectionTest(String url) {
//        String methodName = "testCsrfProtection";
//
//        return MethodSpec.methodBuilder(methodName)
//                .addModifiers(Modifier.PUBLIC)
//                .addAnnotation(Test.class)
//                .addException(Exception.class)
//                .returns(void.class)
//                .addStatement("$T mvcResult = mockMvc.perform($T.get(\"" + url + "\"))\n" +
//                        ".andExpect($T.status().is3xxRedirection())\n" +
//                        ".andReturn()", MvcResult.class, MockMvcRequestBuilders.class, MockMvcResultMatchers.class)
//                .addStatement("$T csrfToken = ($T) mvcResult.getRequest().getAttribute($T.class.getName())\n",
//                        CsrfToken.class, CsrfToken.class, CsrfToken.class)
//                .addStatement("String csrfTokenValue = csrfToken.getToken()\n")
//                .addStatement("mockMvc.perform($T.post(\"http://localhost:8080/leaders\")\n" +
//                        ".param(\"username\", \"raj\")\n" +
//                        ".param(\"password\", \"fun123\")\n" +
//                        ".header(csrfToken.getHeaderName(), csrfTokenValue))\n" +
//                        ".andExpect($T.status().isForbidden())", MockMvcRequestBuilders.class, MockMvcResultMatchers.class)
//                .build();
//    }
//
//    private static MethodSpec attemptSQLInjectionShouldReturnForbidden1(String url) {
//        String methodName = "attemptSQLInjectionShouldReturnForbidden1";
//
//        return MethodSpec.methodBuilder(methodName)
//                .addModifiers(Modifier.PUBLIC)
//                .addAnnotation(Test.class)
//                .addException(Exception.class)
//                .returns(void.class)
//                .addStatement("String maliciousInput = \"1'; DROP TABLE members; --\"")
//                .addStatement("$T formData = new $T<>()", MultiValueMap.class, LinkedMultiValueMap.class)
//                .addStatement("formData.add(\"username\", maliciousInput)")
//                .addStatement("formData.add(\"password\", maliciousInput)")
//                .addStatement("mockMvc.perform($T.post(\"" + url + "\")\n"+
//                        ".contentType($T.APPLICATION_FORM_URLENCODED)\n" +
//                        ".params(formData))\n" +
//                        ".andExpect($T.status().isForbidden())", MockMvcRequestBuilders.class, MediaType.class, MockMvcResultMatchers.class)
//                .build();
//    }
//    private static MethodSpec vulnerableEndpointRedirectTest() {
//        String methodName = "vulnerableEndpointRedirectTest";
//
//        // Build method body
//        return MethodSpec.methodBuilder(methodName)
//                .addModifiers(Modifier.PUBLIC)
//                .addAnnotation(Test.class)
//                .addException(Exception.class)
//                .returns(void.class)
//                .addStatement("String vulnerableEndpoint = $S", "signin")
//                .addStatement("mockMvc.perform($T.get(\"/systems\" + vulnerableEndpoint))\n" +
//                        ".andExpect($T.redirectedUrl(\"http://localhost/showMyLoginPage\"));", MockMvcRequestBuilders.class, MockMvcResultMatchers.class)
//                .build();
//    }
//    private static MethodSpec generateTestMethod(String url) {
//        String methodName = "testMethod";
//
//        // Add AnnotationSpec for @WithMockUser
//        AnnotationSpec withMockUserAnnotation = AnnotationSpec.builder(WithMockUser.class)
//                .addMember("username", "$S", "ravi")
//                .addMember("roles", "{$S}", "ADMIN")
//                .build();
//
//        // Build test method
//        return MethodSpec.methodBuilder(methodName)
//                .addModifiers(Modifier.PUBLIC)
//                .addAnnotation(Test.class)
//                .addAnnotation(withMockUserAnnotation)
//                .addException(Exception.class)
//                .returns(void.class)
//                .addStatement("$T mvcResult = mockMvc.perform($T.get($S))\n" +
//                        ".andExpect($T.status().isOk())\n" +
//                        ".andReturn()", MvcResult.class, MockMvcRequestBuilders.class, url, MockMvcResultMatchers.class)
//                .addStatement("String jwtToken = mvcResult.getResponse().getHeader(\"Authorization\")")
//                .addStatement("System.out.println(\"JWT Token \" + jwtToken)")
//                .addStatement("Assertions.assertTrue(jwtToken != null && jwtToken.startsWith(\"ey\"))")
//                .build();
//    }
//    private static MethodSpec generateTestMethod12344(String url) {
//
//        String methodName = "privilegeEscalationTest";
//        AnnotationSpec testAnnotation = AnnotationSpec.builder(Test.class).build();
//        AnnotationSpec withMockUserAnnotation = AnnotationSpec.builder(WithMockUser.class)
//                .addMember("roles", "{$S}", "MANAGER")
//                .build();
//        return MethodSpec.methodBuilder(methodName)
//                .addModifiers(Modifier.PUBLIC)
//                .addException(Exception.class)
//                .addAnnotation(withMockUserAnnotation)
//                .addAnnotation(testAnnotation)
//                .returns(void.class)
//                .addStatement("mockMvc.perform($T.get($S))\n" +
//                        ".andExpect($T.status().isForbidden())\n" +
//                        ".andExpect($T.content().string($S));", MockMvcRequestBuilders.class, url, MockMvcResultMatchers.class, MockMvcResultMatchers.class, "")
//                .build();
//    }
//
//
//
//    private static MethodSpec generateTestMethod2(String url) {
//        String methodName = "testMethod2";
//
//        AnnotationSpec withMockUserAnnotation = AnnotationSpec.builder(WithMockUser.class)
//                .addMember("username", "$S", "ravi")
//                .addMember("roles", "{$S}", "ADMIN")
//                .build();
//
//        // Build test method
//        return MethodSpec.methodBuilder(methodName)
//                .addModifiers(Modifier.PUBLIC)
//                .addAnnotation(Test.class)
//                .addException(Exception.class)
//                .returns(void.class)
//                .addAnnotation(withMockUserAnnotation)
//                .addStatement("$T mvcResult = mockMvc.perform($T.get($S))\n" +
//                        ".andExpect($T.status().isOk())\n" +
//                        ".andReturn()", MvcResult.class, MockMvcRequestBuilders.class, url, MockMvcResultMatchers.class)
//                .addStatement("String jwtToken = mvcResult.getResponse().getHeader(\"Authorization\")\n")
//                .addStatement("$T.assertTrue(jwtToken.split(\"\\\\.\").length == 3)", Assertions.class)
//                .build();
//    }
//
//    private static MethodSpec generateCreateExpiredJwtTokenMethod() {
//        return MethodSpec.methodBuilder("createExpiredJwtToken")
//                .addModifiers(Modifier.PRIVATE)
//                .returns(String.class)
//                .addStatement("$T now = $T.now()", Instant.class, Instant.class)
//                .addStatement("$T expirationTime = now.minus(36000, $T.SECONDS)", Instant.class, ChronoUnit.class)
//                .addStatement("return $T.builder()\n" +
//                        ".setSubject(\"ravi\")\n" +
//                        ".setExpiration($T.from(expirationTime))\n" +
//                        ".signWith(HS256, \"6bd24ba0c1485ccc121fc11c9f57959b953e2da8e21eda2d766a06fbf265d92\")\n" +
//                        ".compact()", Jwts.class, Date.class)
//                .build();
//    }
//
//    private static MethodSpec generateTestMethod12(String url) {
//        String methodName = "testMethod123";
//
//        AnnotationSpec withMockUserAnnotation = AnnotationSpec.builder(WithMockUser.class)
//                .addMember("username", "$S", "ravi")
//                .addMember("roles", "{$S}", "ADMIN")
//                .build();
//
//        return MethodSpec.methodBuilder(methodName)
//                .addModifiers(Modifier.PUBLIC)
//                .addAnnotation(Test.class)
//                .addException(Exception.class)
//                .returns(void.class)
//                .addAnnotation(withMockUserAnnotation)
//                .addStatement("String expiredToken = createExpiredJwtToken()")
//                .addStatement("mockMvc.perform($T.get($S).header(\"Authorization\", expiredToken))\n" +
//                        ".andExpect($T.status().isOk())", MockMvcRequestBuilders.class, url, MockMvcResultMatchers.class)
//                .build();
//    }
//    private static MethodSpec generateIsWeakAlgorithmMethod() {
//        return MethodSpec.methodBuilder("isWeakAlgorithm")
//                .addModifiers(Modifier.PRIVATE)
//                .returns(boolean.class)
//                .addParameter(String.class, "algorithm")
//                .addStatement("if (algorithm.equals(\"HS512\") || algorithm.equals(\"SHA512\")) {\n" +
//                        "    return false;\n" +
//                        "} else {\n" +
//                        "    return true;}"
//                )
//                .build();
//    }
//    private static MethodSpec generateTestMethod1234(String methodName1) {
//
//        String methodName = "testMethod1234";
//        AnnotationSpec withMockUserAnnotation = AnnotationSpec.builder(WithMockUser.class)
//                .addMember("username", "$S", "ravi")
//                .addMember("roles", "{$S}", "ADMIN")
//                .build();
//
//        return MethodSpec.methodBuilder(methodName)
//                .addModifiers(Modifier.PUBLIC)
//                .addAnnotation(Test.class)
//                .addAnnotation(withMockUserAnnotation)
//                .addException(Exception.class)
//                .returns(void.class)
//                .addStatement("$T mvcResult = mockMvc.perform($T.get($S))\n" +
//                        ".andExpect($T.status().isOk())\n" +
//                        ".andReturn()", MvcResult.class, MockMvcRequestBuilders.class, "/systems", MockMvcResultMatchers.class)
//                .addStatement("String jwtToken = mvcResult.getResponse().getHeader(\"Authorization\")")
//                .addStatement("assert jwtToken != null && jwtToken.startsWith(\"ey\")")
//                .addStatement("String[] tokenParts = jwtToken.split(\"\\\\.\")")
//                .beginControlFlow("if (tokenParts.length < 2)")
//                .addStatement("System.out.println(\"Invalid Jwt Token format\")")
//                .endControlFlow()
//                .addStatement("String encodedHeader = tokenParts[0]")
//                .addStatement("String decodedHeader = new String(java.util.Base64.getUrlDecoder().decode(encodedHeader))")
//                .beginControlFlow("try")
//                .addStatement("Jws<Claims> jws = (Jws<Claims>) Jwts.parser().build().parseSignedClaims(jwtToken).getHeader()")
//                .addStatement("JwsHeader header = jws.getHeader()")
//                .addStatement("String algorithm = header.getAlgorithm()")
//                .addStatement("assertTrue(algorithm.equals(\"HS512\") || isWeakAlgorithm(algorithm), \"Algorithm is not Secure\")")
//                .nextControlFlow("catch (Exception e)")
//                .addStatement("System.out.println(\"Invalid Signature1234\")")
//                .endControlFlow()
//                .build();
//    }
//
//    private static String capitalize(String str) {
//        if (str == null || str.isEmpty()) {
//            return str;
//        }
//        return Character.toUpperCase(str.charAt(0)) + str.substring(1);
//    }


}
