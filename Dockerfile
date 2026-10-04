# syntax=docker/dockerfile:1
ARG GO_VERSION=1.26.3
FROM golang:${GO_VERSION} AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG GIT_SHA=none
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${GIT_SHA} -X main.buildDate=${BUILD_DATE}" \
    -o /out/server ./cmd/server

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/server /server
COPY --from=build /src/migrations /migrations
ENV MIGRATIONS_DIR=/migrations
USER nonroot:nonroot
EXPOSE 9090
ENTRYPOINT ["/server"]
