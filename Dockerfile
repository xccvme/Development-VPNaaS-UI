FROM golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea AS build
WORKDIR /src
ENV GOTOOLCHAIN=local CGO_ENABLED=0
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN go test ./... && go vet ./... && go build -trimpath -ldflags="-s -w -buildid=" -o /out/vpnaas-ui ./cmd/vpnaas-ui

FROM debian:13-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates openssl && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/vpnaas-ui /usr/local/bin/vpnaas-ui
COPY scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh
ENV LISTEN_ADDR=0.0.0.0:8080 UPSTREAM_URL=http://127.0.0.1:8000 API_KEY_FILE=/run/secrets/backend-api.key SESSION_KEY_FILE=/var/lib/vpnaas-ui/session.key
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
