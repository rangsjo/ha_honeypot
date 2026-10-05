FROM python:3.12-slim

WORKDIR /app

# iproute2 + udhcpc for the own_ip option (nsenter/unshare come with the base image)
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 udhcpc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# MAC vendor database. Best-effort: without it alerts just lack the vendor name.
RUN python -c "import urllib.request; urllib.request.urlretrieve('https://www.wireshark.org/download/automated/data/manuf', '/app/manuf')" \
    || echo "WARNING: could not download MAC vendor database"

COPY . /app

RUN chmod +x /app/run.sh /app/udhcpc.script \
    && useradd --system --no-create-home --shell /usr/sbin/nologin honeypot

CMD ["/app/run.sh"]
