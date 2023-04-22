FROM alpine:3.14
EXPOSE 8000
ARG HOST
ARG PORT
ARG USER
ARG PASSWRORD
ARG DB
WORKDIR /www
RUN apk update
RUN apk add openjdk11
RUN apk add git && git clone https://github.com/ATer-Oganisyan/otus-session.git && cd otus-session && jar xf mysql.jar && javac SessionServer.java && apk del git && rm SessionServer.java
ENTRYPOINT java -classpath /www/otus-session SessionServer.java $HOST $PORT $USER $PASSWRORD $DB v1
