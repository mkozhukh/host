FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -o /host .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=build /host /host
EXPOSE 8080
ENTRYPOINT ["/host"]
