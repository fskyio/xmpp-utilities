FROM python:3.14-alpine

WORKDIR /app

COPY pyproject.toml src/ .
RUN pip install --no-cache-dir .

CMD ["xmpp-utilities"]