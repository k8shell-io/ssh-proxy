FROM golang:1.24.5 AS build

ARG VERSION
ARG COMMIT_ID

LABEL VERSION=$VERSION
LABEL COMMIT_ID=$COMMIT_ID

WORKDIR /go/src/ssh-proxy
COPY files .

ENV GOFLAGS="-mod=vendor"

RUN CGO_ENABLED=0 go build -ldflags="-s -w -X internal.server.SSHPROXY_VERSION=$VERSION -X \
    internal.server.SSHPROXY_COMMIT=$COMMIT_ID" -o /go/bin/ssh-proxy main.go

FROM gcr.io/distroless/static-debian12

WORKDIR /app
COPY --from=build /go/bin/ssh-proxy /app

USER nonroot:nonroot
ENTRYPOINT ["/app/ssh-proxy"]
