FROM openjdk:8-jdk-alpine
ADD target/*.jar AuthService-0.0.1-SNAPSHOT.jar
EXPOSE 8091
ENTRYPOINT ["java", "-jar", "AuthService-0.0.1-SNAPSHOT.jar"]

