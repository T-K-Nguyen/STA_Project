# Use Python 3.9 as base image
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Copy all necessary files
COPY *.py /app/
COPY configs.py /app/
COPY hello.txt /app/
COPY hello2.txt /app/

# Create necessary directories
RUN mkdir -p /app/metainfo /app/download

# Install any dependencies (add more if needed)
RUN pip install --no-cache-dir bencodepy

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Expose a range of ports for peer connections
# (Since your peers use random ports)
EXPOSE 6881-6999

# Create a default config file if missing
RUN echo '{"constants": {"BUFFER_SIZE": 4096, "CHUNK_PIECES_SIZE": 1024, "MAX_SPLITTNES_RATE": 5}}' > /app/config.json

# Run the peer node
CMD ["mkdir", "metainfo", "download"]
