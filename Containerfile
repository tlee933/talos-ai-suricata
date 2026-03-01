FROM python:3.12-slim

RUN pip install --no-cache-dir redis requests aiohttp urllib3

COPY *.py /app/
COPY entrypoint.sh /app/

WORKDIR /app
RUN chmod +x entrypoint.sh

EXPOSE 5140 8080

ENTRYPOINT ["./entrypoint.sh"]
