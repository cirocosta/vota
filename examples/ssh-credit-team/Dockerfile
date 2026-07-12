FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/vota ./cmd/vota

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/vota /vota
VOLUME ["/data"]
ENTRYPOINT ["/vota"]
CMD ["serve", "--config", "/data/server.json"]
