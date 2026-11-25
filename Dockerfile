FROM rust:1-slim AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/target/release/pay-gateway /usr/local/bin/pay-gateway
ENV BIND_HOST=0.0.0.0:8787 DB_PATH=/data/orders.db
VOLUME ["/data"]
EXPOSE 8787
USER 65534:65534
ENTRYPOINT ["/usr/local/bin/pay-gateway"]
