FROM python:3.14-alpine

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src/ src/
RUN pip install --no-cache-dir .

CMD ["xmpp-utilities"]