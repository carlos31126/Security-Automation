FROM openjdk:17-jdk-slim

WORKDIR /app

COPY com/security/springboot/demosecurity /app

RUN javac -d . *.java

CMD ["java","com.security.springboot.demosecurity.generateJunitSecurityTestCases"]
