FROM python:3.10-slim

# Disable pip's new "externally managed environment" restriction
ENV PIP_BREAK_SYSTEM_PACKAGES=1

# Install system dependencies for YARA
RUN apt-get update && apt-get install -y \
    libssl-dev \
    libffi-dev \
    python3-dev \
    build-essential \
    libmagic1 \
    curl \
    git \
    autoconf \
    libtool \
    libjansson-dev \
    libssl-dev \
    libmagic-dev \
    pkg-config \
    bison \
    flex \
    && rm -rf /var/lib/apt/lists/*

# Build YARA from source with all modules including math
RUN git clone --recursive https://github.com/VirusTotal/yara.git /tmp/yara && \
    cd /tmp/yara && \
    ./bootstrap.sh && \
    ./configure --enable-magic --enable-cuckoo --with-crypto --enable-dotnet --enable-macho --enable-dex && \
    make && \
    make install && \
    ldconfig && \
    echo "YARA installation completed" && \
    echo "Verifying YARA installation..." && \
    /usr/local/bin/yara --version && \
    cd / && \
    rm -rf /tmp/yara

# Create user with UID 1000 to match host user
RUN groupadd -g 1000 yarauser && useradd -u 1000 -g 1000 -s /bin/bash -m yarauser

# Set working directory
WORKDIR /app

# Copy requirements for YARA service
COPY requirements.yara.txt .
RUN pip install --no-cache-dir --break-system-packages -r requirements.yara.txt

# Copy YARA service files from the new yara_services structure
COPY yara_services/yara_service.py .
COPY yara_services/yara_manager.py ./yara_services/yara_manager.py
COPY yara_services/__init__.py ./yara_services/__init__.py
COPY config/ ./config/

# Create necessary directories with proper permissions
RUN mkdir -p rules logs shared-files yara_services && \
    chown -R yarauser:yarauser /app

# Copy startup script
COPY start_yara.sh ./start_yara.sh
RUN chmod +x start_yara.sh && chown yarauser:yarauser start_yara.sh

# Switch to non-root user
USER 1000:1000

# Expose port
EXPOSE 5001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=120s --retries=3 \
    CMD curl -f http://localhost:5001/health || exit 1

# Run startup script
CMD ["./start_yara.sh"]