FROM golang:1.26-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /policyconsole ./cmd/policyconsole

FROM gcr.io/distroless/static-debian12
COPY --from=build /policyconsole /policyconsole
ENV PC_ADDR=0.0.0.0:8080 PC_DATABASE=/data/policy-console.db
EXPOSE 8080
VOLUME /data
ENTRYPOINT ["/policyconsole"]
