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
RUN apk add git 
RUN git clone https://github.com/ATer-Oganisyan/otus-session.git
RUN cd otus-session && javac SessionServer.java
ENTRYPOINT java -classpath /www/otus-session SessionServer $HOST v19
