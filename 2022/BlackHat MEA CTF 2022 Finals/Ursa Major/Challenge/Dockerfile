FROM python:slim AS app

RUN pip install --no-cache-dir pycryptodome sympy

FROM pwn.red/jail
COPY --from=app / /srv

COPY ursamajor.py /srv/app/run

ENV JAIL_TIME 1200
ENV JAIL_MEM=50M