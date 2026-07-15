# Build stage
FROM rust:1.95-slim AS builder
WORKDIR /app

RUN apt-get update && apt-get install -y \
  git pkg-config \
  && rm -rf /var/lib/apt/lists/*

ENV SQLX_OFFLINE=true

COPY . .
RUN cargo build --release --locked --bin prn

# Runtime stage
FROM debian:stable-slim AS final
WORKDIR /app

RUN apt-get update && apt-get install -y \
  ca-certificates \
  && rm -rf /var/lib/apt/lists/* \
  && update-ca-certificates

COPY --from=builder /app/target/release/prn .

EXPOSE 8080

CMD ["./prn"]
