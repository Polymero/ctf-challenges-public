FROM python:slim AS app

RUN pip install --no-cache-dir pycryptodome

FROM pwn.red/jail
COPY --from=app / /srv

COPY dc_chall.py /srv/app/run
COPY dc_source.py /srv/app

ENV JAIL_TIME 3000
ENV JAIL_MEM=100M