FROM python:3.11.18-slim-trixie

# Creating the app directory
WORKDIR /app

# installing requiements
COPY python/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy only the files required by the scanner and exporter.
COPY python/ ./python/
COPY scripts/ ./scripts/
COPY modules/ ./modules/
COPY config/ ./config/

# execution rights to scripts
RUN chmod +x scripts/*.sh modules/*.sh

# Default command: run full sweep
CMD ["bash", "scripts/securewatch.sh"]
