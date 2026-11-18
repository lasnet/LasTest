# LasTest release image. The builder toolchain is not present in runtime.
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS subfinder
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    case "$(dpkg --print-architecture)" in \
      amd64) arch=amd64; checksum=a39c3e5c7a26ef3c430915c4d6cbf7716a00f26769a75e9405aba796142eba37 ;; \
      arm64) arch=arm64; checksum=24913d49dddc1d3a5e99a4a7580da5be980959b9415b96f52c4f7f4124392190 ;; \
      *) exit 1 ;; \
    esac; \
    curl --fail --location --retry 3 "https://github.com/projectdiscovery/subfinder/releases/download/v2.17.0/subfinder_2.17.0_linux_${arch}.zip" -o /tmp/subfinder.zip; \
    printf '%s  /tmp/subfinder.zip\n' "$checksum" | sha256sum -c -; \
    mkdir /out; unzip -j /tmp/subfinder.zip subfinder LICENSE.md -d /out; chmod 755 /out/subfinder

# LasTest owns scope and wildcard checks; disable dnsmap's implicit DNS probes.
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS dnsmap
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl gcc libc6-dev patch \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN curl --fail --location --retry 3 https://codeload.github.com/resurrecting-open-source-projects/dnsmap/tar.gz/96b17adcdfdcbd5360b92d08ca2eb6ca7c321961 -o /tmp/dnsmap.tar.gz \
    && echo 'df3e6311fe07b5bd90e9c28a575b50c020b8026861ebf9f80aac20f9d2a836b4  /tmp/dnsmap.tar.gz' | sha256sum -c - \
    && tar -xzf /tmp/dnsmap.tar.gz --strip-components=1
COPY src/tasks/dnsmap-probes.patch /tmp/dnsmap-probes.patch
RUN patch -p1 < /tmp/dnsmap-probes.patch \
    && mkdir /out && gcc -O2 src/dnsmap.c -o /out/dnsmap \
    && cp COPYING /out/COPYING

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
COPY --from=dnsmap /out/dnsmap /usr/local/bin/dnsmap
COPY --from=dnsmap /out/COPYING /usr/share/licenses/dnsmap/COPYING
COPY --from=dnsmap /tmp/dnsmap.tar.gz /usr/share/licenses/dnsmap/source.tar.gz
COPY src/tasks/dnsmap-probes.patch /usr/share/licenses/dnsmap/dnsmap-probes.patch
COPY --from=subfinder /out/subfinder /usr/local/bin/subfinder
COPY --from=subfinder /out/LICENSE.md /usr/share/licenses/subfinder/LICENSE.md
ENV LASTEST_DATA_DIR=/data \
    LASTEST_BIND=0.0.0.0:8080 \
    LASTEST_LOG_LEVEL=info \
    LASTEST_SUBFINDER_PATH=/usr/local/bin/subfinder \
    LASTEST_DNSMAP_PATH=/usr/local/bin/dnsmap
USER 10001:10001
EXPOSE 8080
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/lastest"]
CMD ["serve"]
