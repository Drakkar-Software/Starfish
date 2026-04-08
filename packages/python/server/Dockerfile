FROM python:3.12-slim
WORKDIR /app
COPY packages/python/protocol/ /app/protocol/
COPY packages/python/server/ /app/server/
RUN pip install --no-cache-dir /app/protocol /app/server
EXPOSE 8000
# Run the example server; replace with your own app module as needed.
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000", "--app-dir", "/app/server"]
