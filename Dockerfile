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

# dnsx 1.3.1; queries go through LasTest's private rate-limited DNS relay.
FROM subfinder AS dnsx
RUN set -eu; \
    case "$(dpkg --print-architecture)" in \
      amd64) arch=amd64; checksum=438b964653056dd51dcfe614b1a16f8bced3cc48a1d27bc07cc6fdf2ef2a9533 ;; \
      arm64) arch=arm64; checksum=dd657dd1ccee5e137eca2dbad0e97dbd067555f744adb97efcda774f1b2fbde1 ;; \
      *) exit 1 ;; \
    esac; \
    curl --fail --location --retry 3 "https://github.com/projectdiscovery/dnsx/releases/download/v1.3.1/dnsx_1.3.1_linux_${arch}.zip" -o /tmp/dnsx.zip; \
    printf '%s  /tmp/dnsx.zip\n' "$checksum" | sha256sum -c -; \
    mkdir /dnsx; unzip -j /tmp/dnsx.zip dnsx LICENSE.md -d /dnsx; chmod 755 /dnsx/dnsx

# WhatWeb 0.6.4. The plugin loader requires both directories, even when my-plugins is empty.
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS whatweb
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN curl --fail --location --retry 3 https://codeload.github.com/urbanadventurer/WhatWeb/tar.gz/d279d93042d034f3fd29d5a893d44ccc0595d3f8 -o /tmp/whatweb.tar.gz \
    && echo 'f239c8d23b9b1d92d896351236ce0c00f08316897f8581212228adf13c521495  /tmp/whatweb.tar.gz' | sha256sum -c - \
    && tar -xzf /tmp/whatweb.tar.gz --strip-components=1 \
    && mkdir -p /out/plugins /out/my-plugins \
    && cp -R whatweb lib LICENSE /out/ \
    && cp plugins/jenkins.rb plugins/jquery.rb /out/plugins/ \
    && chmod 755 /out/whatweb

FROM rust:1.100-bookworm@sha256:ade39a710ef85f3506cffcfec3e8a24ba090badef1dff2fb798f71d878833fea AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
COPY migrations ./migrations
COPY ui ./ui
RUN cargo build --locked --release

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates ruby ruby-addressable \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 lastest \
    && useradd --uid 10001 --gid 10001 --home-dir /data --no-create-home --shell /usr/sbin/nologin lastest \
    && mkdir -p /data/evidence /data/tmp \
    && chown -R 10001:10001 /data
COPY --from=build /src/target/release/lastest /usr/local/bin/lastest
COPY --from=dnsx /dnsx/dnsx /usr/local/bin/dnsx
COPY --from=dnsx /dnsx/LICENSE.md /usr/share/licenses/dnsx/LICENSE.md
COPY src/tasks/wordlists/ /usr/share/licenses/dns-wordlist/
COPY --from=subfinder /out/subfinder /usr/local/bin/subfinder
COPY --from=subfinder /out/LICENSE.md /usr/share/licenses/subfinder/LICENSE.md
COPY --from=whatweb /out/ /opt/whatweb/
COPY --from=whatweb /tmp/whatweb.tar.gz /usr/share/licenses/whatweb/source.tar.gz
ENV LASTEST_DATA_DIR=/data \
    LASTEST_BIND=0.0.0.0:8080 \
    LASTEST_LOG_LEVEL=info \
    LASTEST_SUBFINDER_PATH=/usr/local/bin/subfinder \
    LASTEST_DNSX_PATH=/usr/local/bin/dnsx \
    LASTEST_WHATWEB_PATH=/opt/whatweb/whatweb
USER 10001:10001
EXPOSE 8080
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/lastest"]
CMD ["serve"]
