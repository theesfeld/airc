# syntax=docker/dockerfile:1

FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/airc ./cmd/airc
RUN mkdir -p /out/data && touch /out/data/.keep

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/airc /airc
# static distroless has no CA bundle. AI calls need one. The image sets
# SSL_CERT_FILE to this path.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=65532:65532 /out/data /data
WORKDIR /data
VOLUME ["/data"]
EXPOSE 6697
ENTRYPOINT ["/airc"]
CMD ["run", "-config", "/data/airc.yaml"]
