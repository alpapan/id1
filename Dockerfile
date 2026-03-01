FROM golang:1.23 AS build

WORKDIR /go/src/app
COPY main.go_ ./main.go

RUN go mod init id1.au/id1 && \
    go get github.com/joho/godotenv@v1.5.1 && \
    go get github.com/qodex/id1@v1.0.1 && \
    CGO_ENABLED=0 go build -ldflags="-X main.version=$(date +%Y%m%d)" -o /go/bin/app

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /go/bin/app /
CMD ["/app"]