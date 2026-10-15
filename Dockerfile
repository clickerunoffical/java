FROM eclipse-temurin:21-jdk
WORKDIR /app
COPY CyberSecurityScanner.java .
RUN javac --add-modules jdk.httpserver CyberSecurityScanner.java
ENV PORT=8080
EXPOSE 8080
CMD ["java", "--add-modules", "jdk.httpserver", "CyberSecurityScanner"]
