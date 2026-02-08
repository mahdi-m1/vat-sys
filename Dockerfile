# =====================================================
# VAT Tax System v3.0.0 - Dockerfile
# =====================================================

FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # OCR dependencies
    tesseract-ocr \
    tesseract-ocr-ara \
    tesseract-ocr-eng \
    # PDF processing
    poppler-utils \
    # Image processing
    libpng-dev \
    libjpeg-dev \
    # PostgreSQL client
    libpq-dev \
    # Build tools
    gcc \
    g++ \
    # Utilities
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/storage/uploads /app/storage/reports /app/logs

# Set permissions
RUN chmod +x /app/app.py

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/api/health || exit 1

# Run the application
CMD ["python", "app.py"]
