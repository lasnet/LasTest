# LasTest release image. The builder toolchain is not present in runtime.
FROM rust:1.100-bookworm@sha256:ade39a710ef85f3506cffcfec3e8a24ba090badef1dff2fb798f71d878833fea AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
COPY migrations ./migrations
COPY ui ./ui
RUN cargo build --locked --release

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 lastest \
    && useradd --uid 10001 --gid 10001 --home-dir /data --no-create-home --shell /usr/sbin/nologin lastest \
    && mkdir -p /data/evidence /data/tmp \
    && chown -R 10001:10001 /data
COPY --from=build /src/target/release/lastest /usr/local/bin/lastest
ENV LASTEST_DATA_DIR=/data \
    LASTEST_BIND=0.0.0.0:8080 \
    LASTEST_LOG_LEVEL=info
USER 10001:10001
EXPOSE 8080
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/lastest"]
CMD ["serve"]
