FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# MAC vendor database. Best-effort: without it alerts just lack the vendor name.
RUN python -c "import urllib.request; urllib.request.urlretrieve('https://www.wireshark.org/download/automated/data/manuf', '/app/manuf')" \
    || echo "WARNING: could not download MAC vendor database"

COPY . /app

RUN chmod +x /app/run.sh

CMD ["/app/run.sh"]
