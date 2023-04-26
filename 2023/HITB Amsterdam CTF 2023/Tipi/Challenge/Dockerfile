FROM python:slim AS app

WORKDIR /app

RUN pip install --no-cache-dir pycryptodome

COPY . /app

ENTRYPOINT [ "python" ]

CMD [ "tipi.py" ]