# syntax=docker/dockerfile:1

############################
# Build stage
############################
FROM eclipse-temurin:21-jdk AS builder

WORKDIR /app

# Copy Maven wrapper first
COPY .mvn/ .mvn/
COPY mvnw pom.xml ./

RUN chmod +x mvnw

# Download dependencies (cached unless pom.xml changes)
RUN ./mvnw dependency:go-offline

# Copy application source
COPY src/ src/

# Build
RUN ./mvnw clean package -DskipTests spring-boot:repackage

############################
# Runtime stage
############################
FROM eclipse-temurin:21-jre

WORKDIR /app

COPY --from=builder /app/target/server-0.0.1-SNAPSHOT.jar app.jar

EXPOSE 5000

ENTRYPOINT ["java","-XX:+UseContainerSupport","-XX:MaxRAMPercentage=75.0","-jar","/app/app.jar"]