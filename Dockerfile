FROM kalilinux/kali-rolling AS go-tools

ENV DEBIAN_FRONTEND=noninteractive \
    GOBIN=/out

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        git \
        golang \
        libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /out /tmp/gopath /tmp/gocache \
    && GOCACHE=/tmp/gocache GOPATH=/tmp/gopath GOBIN=/out \
        go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && GOCACHE=/tmp/gocache GOPATH=/tmp/gopath GOBIN=/out \
        go install github.com/hakluke/hakrevdns@latest \
    && GOCACHE=/tmp/gocache GOPATH=/tmp/gopath GOBIN=/out \
        go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && GOCACHE=/tmp/gocache GOPATH=/tmp/gopath GOBIN=/out \
        go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && GOCACHE=/tmp/gocache GOPATH=/tmp/gopath GOBIN=/out \
        go install github.com/lc/gau/v2/cmd/gau@latest \
    && GOCACHE=/tmp/gocache GOPATH=/tmp/gopath GOBIN=/out \
        go install github.com/tomnomnom/waybackurls@latest \
    && GOCACHE=/tmp/gocache GOPATH=/tmp/gopath GOBIN=/out CGO_ENABLED=1 \
        go install github.com/projectdiscovery/katana/cmd/katana@latest \
    && rm -rf /tmp/gopath /tmp/gocache /root/.cache /root/go


FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VIRTUAL_ENV=/opt/venv \
    GOBIN=/opt/go/bin \
    PATH="/opt/venv/bin:/opt/go/bin:${PATH}"

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        amass \
        ca-certificates \
        curl \
        dnsmap \
        dnsutils \
        ffuf \
        git \
        nikto \
        nmap \
        proxychains4 \
        python3 \
        python3-pip \
        python3-venv \
        sqlmap \
        theharvester \
        whatweb \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN python3 -m venv /opt/venv \
    && pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY --from=go-tools /out/ /opt/go/bin/

COPY . .

RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /app/projects /app/data /app/logs \
    && chown -R appuser:appuser /app /opt/venv /opt/go

USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
