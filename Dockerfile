FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/domain-doctor ./cmd/domain-doctor

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/domain-doctor /usr/local/bin/domain-doctor
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/domain-doctor"]
