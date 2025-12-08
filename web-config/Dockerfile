FROM python:3.11-alpine

# Install nginx and dependencies
RUN apk add --no-cache \
    nginx \
    supervisor \
    curl

# Create directories
RUN mkdir -p /app /var/log/supervisor /run/nginx

WORKDIR /app

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY index.html styles.css script.js /usr/share/nginx/html/
COPY api.py /app/
COPY nginx.conf /etc/nginx/nginx.conf
COPY supervisord.conf /etc/supervisord.conf

# Expose ports
EXPOSE 80 8000

# Start supervisor (manages nginx + FastAPI)
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
