FROM golang:1.24.13-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/ebi ./cmd/ebi && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/ebi-server ./cmd/ebi-server && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/ebi-monitor ./cmd/ebi-monitor && \
    mkdir -p /out/ebi-data /out/ebi-monitor-data /out/ebi-config

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder --chown=nonroot:nonroot /out/ebi /ebi
COPY --from=builder --chown=nonroot:nonroot /out/ebi-server /ebi-server
COPY --from=builder --chown=nonroot:nonroot /out/ebi-monitor /ebi-monitor
COPY --from=builder --chown=nonroot:nonroot /out/ebi-data /var/lib/ebi
COPY --from=builder --chown=nonroot:nonroot /out/ebi-monitor-data /var/lib/ebi-monitor
COPY --from=builder --chown=nonroot:nonroot /out/ebi-config /etc/ebi
ENV EBI_PORT=8080
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/ebi-server"]
