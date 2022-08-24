FROM alpine:latest

RUN apk update && apk add curl && apk add stress-ng
COPY ./pod-to-pod.sh /
COPY ./pod-to-external.sh /
COPY ./cpu-hog.sh /
