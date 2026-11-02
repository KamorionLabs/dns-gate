# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM node:22-alpine AS ui
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src/eurodns-gate
ARG VERSION=dev
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=ui /src/web/dist ./web/dist
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-s -w -X github.com/KamorionLabs/eurodns-gate/internal/version.Version=${VERSION}" \
      -o /out/eurodns-gate ./cmd/eurodns-gate

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/eurodns-gate /eurodns-gate
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/eurodns-gate"]
