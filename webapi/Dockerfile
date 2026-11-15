FROM python:3.11-slim
WORKDIR /app
COPY webapi/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY webapi/ /app/webapi/
COPY scripts/ /app/scripts/
COPY modules/ /app/modules/
COPY config/ /app/config/
COPY python/ /app/python/
RUN mkdir -p /app/data/logs /app/data/reports /app/data/state

ENV WEBAPI_DB_PATH=/app/data/state/securewatch.db
EXPOSE 8000
CMD ["uvicorn", "webapi.main:app", "--host", "0.0.0.0", "--port", "8000"]
