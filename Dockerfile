# Two distinct args, not one: the build stage's base (golang) and the runtime
# stage's base (distroless) come from different public registries, so a single
# shared arg cannot default correctly to both at once. Each defaults to its real
# upstream registry so a bare `docker build` (a standalone clone, or
# annot8r_id1's separate build script) resolves both stages unchanged. Curatorium's
# own build overrides both via skaffold.yaml.template's buildArgs, pointing every
# base image at its resolved local registry mirror instead.
ARG GOLANG_REGISTRY_HOST=docker.io
ARG DISTROLESS_REGISTRY_HOST=gcr.io
FROM ${GOLANG_REGISTRY_HOST}/golang:1.25 AS build

# Go build tags. Empty by default so an unparameterised build (e.g. a bare
# `docker build` outside skaffold, or annot8r_id1's separate build script)
# carries neither the arbitrary-ORCID /auth/test_user mint (`testmint`) nor the
# demo-identity /auth/unauth_demo mint (`curatoriumdemo`) - the fail-closed
# default for both capabilities. Curatorium's build always passes GO_TAGS with
# `curatoriumdemo` included (see commands_build.py's id1_go_tags), since the
# four demo pages depend on that mint in every Curatorium environment,
# production included.
ARG GO_TAGS=""

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
    CGO_ENABLED=0 go build -tags="${GO_TAGS}" -ldflags="-X main.version=$(date +%Y%m%d)" -o /go/bin/app

FROM ${DISTROLESS_REGISTRY_HOST}/distroless/static-debian12:nonroot

COPY --from=build /go/bin/app /
CMD ["/app"]

# __END_OF_FILE_MARKER__