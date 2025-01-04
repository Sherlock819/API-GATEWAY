# Use an official openjdk runtime as a parent image
FROM openjdk:20-jdk

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY target/api-gateway-0.0.1-SNAPSHOT.jar /app/target/api-gateway-0.0.1-SNAPSHOT.jar

# Run the application
ENTRYPOINT ["java", "-jar", "target/api-gateway-0.0.1-SNAPSHOT.jar"]