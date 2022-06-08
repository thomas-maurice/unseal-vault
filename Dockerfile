FROM golang:alpine
ADD . /usr/src/unseal-vault
WORKDIR /usr/src/unseal-vault
RUN go build

FROM alpine:latest
RUN apk --update add ca-certificates
COPY --from=0 /usr/src/unseal-vault/unseal-vault /unseal-vault
