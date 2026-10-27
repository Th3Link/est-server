# Static musl binary in a distroless image.
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev gcc
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p est-server \
 && strip target/release/est-server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /src/target/release/est-server /usr/local/bin/est-server
USER nonroot:nonroot
EXPOSE 8443 8080
ENV EST_SERVER_CONFIG=/etc/est-server/est-server.toml
ENTRYPOINT ["/usr/local/bin/est-server"]
CMD ["serve"]
