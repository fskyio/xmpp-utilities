FROM python:3.14-alpine

WORKDIR /app

COPY main.py .
RUN python -m pip install --no-cache-dir slixmpp dnspython

CMD ["python", "main.py"]
