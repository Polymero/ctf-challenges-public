FROM python:slim AS app

WORKDIR /app

RUN apt update \
    && apt install -y socat \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir pycryptodome

COPY . /app

EXPOSE 5000
CMD ["socat", "-T300", "-d", "-d", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:/usr/local/bin/python3 /app/chall.py,pty,raw,stderr,echo=0"]