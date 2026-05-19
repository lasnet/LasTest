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
        build-essential \
        ca-certificates \
        curl \
        dnsmap \
        dnsutils \
        ffuf \
        git \
        golang \
        libpcap-dev \
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

RUN mkdir -p /opt/go/bin \
    && go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install github.com/hakluke/hakrevdns@latest \
    && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install github.com/lc/gau/v2/cmd/gau@latest \
    && go install github.com/tomnomnom/waybackurls@latest \
    && CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest

COPY . .

RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /app/projects /app/data /app/logs \
    && chown -R appuser:appuser /app /opt/venv

USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

