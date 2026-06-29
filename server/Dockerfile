# syntax=docker/dockerfile:1

FROM eclipse-temurin:21-jdk AS builder

WORKDIR /app

COPY .mvn .mvn
COPY mvnw .
COPY pom.xml .

RUN chmod +x mvnw

# Download dependencies
RUN ./mvnw dependency:go-offline

# Copy source
COPY src src

# Build application
RUN ./mvnw clean package -DskipTests


# ---------------- Runtime image ----------------

FROM eclipse-temurin:21-jre

WORKDIR /app

COPY --from=builder /app/target/server-0.0.1-SNAPSHOT.jar app.jar

EXPOSE 5000

ENTRYPOINT ["java","-XX:+UseContainerSupport","-XX:MaxRAMPercentage=75.0","-jar","app.jar"]