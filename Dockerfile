FROM python:3.13-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-client ca-certificates curl unzip \
        default-jre-headless \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt 'sqlmap==1.10.11' 'zaproxy==0.6.0' pyyaml six

RUN curl -fsSL -o /tmp/ffuf.tar.gz https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz \
    && mkdir -p /tmp/ffuf \
    && tar -xzf /tmp/ffuf.tar.gz -C /tmp/ffuf \
    && find /tmp/ffuf -type f -name ffuf -exec mv {} /usr/local/bin/ffuf \; \
    && chmod 755 /usr/local/bin/ffuf \
    && rm -rf /tmp/ffuf /tmp/ffuf.tar.gz

RUN curl -fsSL -o /tmp/nuclei.zip https://github.com/projectdiscovery/nuclei/releases/download/v3.4.7/nuclei_3.4.7_linux_amd64.zip \
    && unzip -o /tmp/nuclei.zip nuclei -d /usr/local/bin \
    && chmod 755 /usr/local/bin/nuclei \
    && rm -f /tmp/nuclei.zip

RUN curl -fsSL -o /tmp/zap.tar.gz https://github.com/zaproxy/zaproxy/releases/download/v2.16.1/ZAP_2.16.1_Linux.tar.gz \
    && mkdir -p /opt/zap \
    && tar -xzf /tmp/zap.tar.gz -C /opt/zap --strip-components=1 \
    && ln -s /opt/zap /zap \
    && ln -sf zap.sh /opt/zap/zap-x.sh \
    && chmod -R a+rX /opt/zap \
    && rm -f /tmp/zap.tar.gz \
    && curl -fsSL -o /usr/local/bin/zap-baseline.py https://raw.githubusercontent.com/zaproxy/zaproxy/v2.16.1/docker/zap-baseline.py \
    && curl -fsSL -o /usr/local/bin/zap_common.py https://raw.githubusercontent.com/zaproxy/zaproxy/v2.16.1/docker/zap_common.py \
    && chmod 755 /usr/local/bin/zap-baseline.py /usr/local/bin/zap_common.py

COPY wordlists/common.txt /opt/charter/wordlist.txt
COPY scanners/nuclei /opt/nuclei-templates
RUN chmod -R a+rX /opt/charter /opt/nuclei-templates \
    && python -c "import shutil; missing=[n for n in ('ffuf','nuclei','sqlmap','zap-baseline.py') if not shutil.which(n)]; assert not missing, missing"

COPY charter.py lab.py ./
COPY app app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/tmp \
    CHARTER_WORDLIST=/opt/charter/wordlist.txt \
    CHARTER_NUCLEI_TEMPLATES=/opt/nuclei-templates
USER 65534:65534
CMD ["python", "-m", "app.web"]
