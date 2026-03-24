FROM golang:1.25 AS build

# Copy id1 library source (package github.com/qodex/id1)
WORKDIR /go/src/app
COPY . .

# Build the main binary from a separate module that references the local id1 library
RUN mkdir -p /go/src/cmd
COPY main.go_ /go/src/cmd/main.go
RUN cd /go/src/cmd && \
    go mod init id1-main && \
    go mod edit -replace github.com/qodex/id1=/go/src/app && \
    go get github.com/joho/godotenv@v1.5.1 && \
    go mod tidy && \
    CGO_ENABLED=0 go build -ldflags="-X main.version=$(date +%Y%m%d)" -o /go/bin/app

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /go/bin/app /
CMD ["/app"]

# __END_OF_FILE_MARKER__