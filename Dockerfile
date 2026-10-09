FROM golang:1.27.1-bookworm AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/quantumgate ./cmd/quantumgate
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/qg-migrate ./cmd/qg-migrate
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/qg-bootstrap ./cmd/qg-bootstrap

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=65532:65532 /out/quantumgate /quantumgate
COPY --from=build --chown=65532:65532 /out/qg-migrate /qg-migrate
COPY --from=build --chown=65532:65532 /out/qg-bootstrap /qg-bootstrap

USER 65532:65532
EXPOSE 8443 9443
ENTRYPOINT ["/quantumgate"]
