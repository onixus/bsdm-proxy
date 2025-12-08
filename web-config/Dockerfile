FROM python:3.11-alpine

# Install nginx, supervisor and build dependencies for psutil
RUN apk add --no-cache \
    nginx \
    supervisor \
    curl \
    gcc \
    python3-dev \
    musl-dev \
    linux-headers \
    docker-cli

# Create directories
RUN mkdir -p /app /var/log/supervisor /run/nginx /config

WORKDIR /app

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Clean up build dependencies to reduce image size
RUN apk del gcc python3-dev musl-dev linux-headers

# Copy application files
COPY index.html styles.css script.js monitoring.js /usr/share/nginx/html/
COPY api.py /app/
COPY nginx.conf /etc/nginx/nginx.conf
COPY supervisord.conf /etc/supervisord.conf

# Copy default config template to /config inside container
COPY ../config/.env.example /config/.env.example

# Expose ports
EXPOSE 80 8000

# Start supervisor (manages nginx + FastAPI)
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
