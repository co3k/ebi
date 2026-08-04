FROM golang:1.24.13-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/ebi-server ./cmd/ebi-server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder --chown=nonroot:nonroot /out/ebi-server /ebi-server
ENV EBI_PORT=8080
ENV EBI_DATA_DIR=/tmp/ebi
ENV EBI_CHECKPOINT_STATE=/tmp/ebi/checkpoint-state
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/ebi-server"]
