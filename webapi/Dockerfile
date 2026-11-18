FROM python:3.11.18-slim-trixie
WORKDIR /app
COPY webapi/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY webapi/ /app/webapi/
COPY scripts/ /app/scripts/
COPY modules/ /app/modules/
COPY config/ /app/config/
COPY python/ /app/python/
RUN install -d -o 1000 -g 1000 -m 0750 /app/data/logs /app/data/state

ENV WEBAPI_DB_PATH=/app/data/state/securewatch.db
ENV PYTHONDONTWRITEBYTECODE=1
EXPOSE 8000
USER 1000:1000
CMD ["uvicorn", "webapi.main:app", "--host", "0.0.0.0", "--port", "8000"]
