FROM python:slim AS app

RUN pip install --no-cache-dir pycryptodome sympy

FROM pwn.red/jail
COPY --from=app / /srv

COPY lweke.py /srv/app/run

ENV JAIL_TIME 3000
ENV JAIL_MEM=100M