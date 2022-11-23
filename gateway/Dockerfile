# STAGE 1: BUILD ###
FROM maven:3.8.5-openjdk-11 AS builders
#create app directory in image and copies pom.xml
COPY pom.xml /app/
#copy source into the app directory in image
COPY src /app/src
#set app as directory into the app
WORKDIR /app/
RUN mvn clean install
#LABEL Name=internalapp Version=0.0.1
#RUN apt-get -y update && apt-get install -y fortunes
#CMD ["sh", "-c", "/usr/games/fortune -a | cowsay"]


FROM openjdk:11.0.12-jdk
WORKDIR /app
COPY --from=builders /app/target/gateway-0.0.1.jar /app/
ENTRYPOINT ["java", "-jar", "gateway-0.0.1.jar"]
