# ovenmitt daemon image. Build from the repo root:
#   docker build -f docker/Dockerfile -t ovenmitt .
# The binary is built inside the container for the container's own
# architecture; never cross-compiled from the host (DEVELOPMENT.md D-8).

FROM rust:1.97-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
RUN cargo build --release --locked && strip target/release/ovenmitt

FROM debian:bookworm-slim
RUN groupadd --system ovenmitt \
 && useradd --system --gid ovenmitt --home-dir /var/lib/ovenmitt --shell /usr/sbin/nologin ovenmitt \
 && mkdir -p /var/lib/ovenmitt/data /var/lib/ovenmitt/keys /var/lib/ovenmitt/audit \
             /var/lib/ovenmitt/export/archive /run/ovenmitt /etc/ovenmitt \
 && chown -R ovenmitt:ovenmitt /var/lib/ovenmitt /run/ovenmitt
COPY --from=build /src/target/release/ovenmitt /usr/local/bin/ovenmitt
RUN ln -s /usr/local/bin/ovenmitt /usr/local/bin/ovenmittd
COPY docker/example/ovenmitt.toml /etc/ovenmitt/ovenmitt.toml
USER ovenmitt
VOLUME ["/var/lib/ovenmitt/data", "/var/lib/ovenmitt/keys", "/var/lib/ovenmitt/audit", "/run/ovenmitt"]
ENTRYPOINT ["/usr/local/bin/ovenmitt"]
CMD ["daemon"]
