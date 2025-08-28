# 🔬 PRIMAL v2.0 - Personal Malware Analysis Lab

**PR**ism  **I**nfosec **M**alware **A**nalysis **L**ab

A comprehensive, containerized malware analysis platform built with a microservices architecture for scalable, multi-engine static analysis.

![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)
![Docker](https://img.shields.io/badge/docker-required-blue.svg)
![Python](https://img.shields.io/badge/python-3.10-green.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)


## 🌟 Features

### 🛡️ Multi-Engine Antivirus Scanning
- **Containerized Engines**: ClamAV running in isolated Docker container
- **Remote API Integration**: VirusTotal, Hybrid Analysis, MetaDefender
- **Extensible Architecture**: Easy addition of new AV engines
- **Real-time Results**: Live scanning with detailed threat analysis

### 🔍 Advanced Analysis Capabilities
- **YARA Rule Scanning**: Custom and community rule sets
- **Configurable String Extraction**: Regex patterns, API calls, suspicious keywords
- **File Type Analysis**: Magic number detection and metadata extraction
- **Hash Analysis**: MD5, SHA256 calculation and verification

### 🎯 Threat Hunting & IOC Generation
- **KQL Query Generation**: Microsoft Defender queries for threat hunting
- **YARA Rule Creation**: Automatic rule generation from samples
- **IOC Export**: JSON, CSV, STIX, MISP formats
- **Detection Engineering**: Custom detection content creation

### 📊 Comprehensive Reporting
- **Multiple Report Types**: Summary, detailed, and threat-focused reports
- **Export Formats**: JSON, CSV, PDF-ready HTML
- **Historical Analysis**: Track analysis over time
- **Comparison Analytics**: Cross-engine result analysis

### 🏗️ Microservices Architecture
- **Container Isolation**: Each AV engine in dedicated container
- **Horizontal Scaling**: Scale individual components independently
- **Fault Tolerance**: Service failures don't affect other engines
- **Easy Expansion**: Add new engines without code changes

## 🏛️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    PRIMAL v2.0 Architecture                │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────┐    ┌─────────────────┐                │
│  │  Web Interface  │    │   File Upload   │                │
│  │     (Flask)     │    │   & Storage     │                │
│  └─────────────────┘    └─────────────────┘                │
│           │                       │                        │
│  ┌─────────────────────────────────────────────────────────┐│
│  │            Main Orchestrator Container              ││
│  │  • YARA Rule Scanning                               ││
│  │  • String Analysis Engine                           ││
│  │  • Database Management                              ││
│  │  • Remote API Integration (VT, HA, MD)              ││
│  │  • Report Generation                                ││
│  │  • Threat Hunting & IOC Generation                  ││
│  └─────────────────────────────────────────────────────────┘│
│           │                                                 │
│  ┌─────────────────────────────────────────────────────────┐│
│  │                 Shared File Storage                 ││
│  └─────────────────────────────────────────────────────────┘│
│           │                                                 │
│  ┌─────────────────┐    ┌─────────────────┐                │
│  │  ClamAV Service │    │ Future AV Engine│                │
│  │   (Container)   │    │   (Container)   │                │
│  │  • REST API     │    │  • REST API     │                │
│  │  • Auto-updates │    │  • Isolated     │                │
│  │  • Health Check │    │  • Configurable │                │
│  └─────────────────┘    └─────────────────┘                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- **Docker & Docker Compose**: Version 20.10+ recommended
- **8GB RAM**: Minimum for running all services
- **10GB Disk Space**: For containers, databases, and file storage
- **Network Access**: For remote API services (optional)

### Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/your-org/primal-v2.git
   cd primal-v2
   ```

2. **Configure Environment**
   ```bash

   #Install Docker and setup environment
   chmod +x docker_setup.sh
   ./docker_setup.sh

   # Copy environment template
   cp .env.example .env
   
   # Edit configuration
   nano .env
   ```

3. **Add Yara Rules**
   ```
   Grab any rules you want from: https://github.com/InQuest/awesome-yara
   and put them in /rules - you can have nested folders here.
   WHen the you start primal, the orchestrator container will compile
   thes rules, this will mean it will be slower if ou have thousands of rules.
   Rules with issues will not cause the compilation to fail - they are handled gracefully
   , and you can see what  they are in the docker logs.
   ```
   
4. **Build the Platform**
   ```bash
   # Build and start all services
   sudo docker-compose build
   
   # Check service status
   sudo docker-compose ps
   ```

5. **Start the Platform**
   ```bash
   # Build and start all services
   sudo docker-compose up -d
   
   # Check service status
   sudo docker-compose ps
   ```

6. **Access the Interface**
   ```
   🌐 Web Interface: http://0.0.0.0:8080
   📊 Container Health: http://0.0.0.0:8080/api/containers/health
   ```

## ⚙️ Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# Security
SECRET_KEY=your-super-secret-key-change-this-in-production

# API Keys (Optional - for remote engines)
VIRUSTOTAL_API_KEY=your_virustotal_api_key
HYBRID_ANALYSIS_API_KEY=your_hybrid_analysis_api_key  
METADEFENDER_API_KEY=your_metadefender_api_key

# Container URLs (Auto-configured)
CLAMAV_URL=http://clamav-scanner:5000

# Flask Environment
FLASK_ENV=production
PYTHONUNBUFFERED=1
```

### Container Resources

Adjust resource limits in `docker-compose.yml`:

```yaml
deploy:
  resources:
    limits:
      memory: 2G      # Maximum memory per container
      cpus: '1.0'     # Maximum CPU cores
    reservations:
      memory: 512M    # Reserved memory
      cpus: '0.5'     # Reserved CPU
```

## 📖 Usage Guide

### 🔬 Basic Analysis Workflow

1. **Upload Sample**
   - Navigate to the main page
   - Drag & drop or click to upload file
   - Supports any file type, up to 100MB

2. **Automatic Analysis**
   - YARA rules scanning
   - Multi-engine AV scanning  
   - String extraction & analysis
   - Metadata extraction

3. **Review Results**
   - Detailed analysis page with all findings
   - AV engine results with threat scores
   - YARA rule matches with metadata
   - Extracted strings categorization

4. **Generate Intelligence**
   - Create threat hunting queries (KQL)
   - Generate YARA detection rules
   - Export IOCs in multiple formats
   - Generate comprehensive reports

### 🛡️ Antivirus Engine Management

Access the AV management page to:

- **Configure Engines**: Enable/disable individual engines
- **Add API Keys**: Configure remote service credentials
- **Check Health**: Monitor container service status
- **Update Signatures**: Refresh AV definitions

### 📋 YARA Rule Management

- **Upload Rules**: Add custom YARA rules by directory
- **Browse Collection**: View and search existing rules
- **Test Rules**: Validate rule syntax and patterns
- **Auto-reload**: Automatically refresh rule changes

### 🔧 String Analysis Configuration

Customize string extraction:

- **Regex Patterns**: Define custom extraction patterns
- **API Call Detection**: Configure Windows API monitoring
- **Suspicious Keywords**: Set malware indicator terms
- **Extraction Settings**: Control length limits and filters

## 🔌 API Reference

### Container Management

```bash
# Check container health
GET /api/containers/health

# Add new AV engine container
POST /api/containers/add
{
  "engine_id": "defender",
  "name": "Windows Defender", 
  "url": "http://defender:5000",
  "enabled": true
}
```

### File Analysis

```bash
# Upload and analyze file
POST /upload
Content-Type: multipart/form-data

# Get analysis results
GET /api/files/{file_id}

# Rescan with AV engines
POST /api/av/scan/{file_id}

# Check submitted analysis status
POST /api/analysis/update/{file_id}
```

### Threat Hunting

```bash
# Generate threat hunting content
GET /api/threat-hunting/{file_id}

# Export detection content
GET /api/threat-hunting/export/{file_id}/{type}
# Types: kql, yara, iocs_json, iocs_csv, stix, misp
```

### Reports

```bash
# Generate analysis report
POST /api/reports/generate
{
  "type": "summary|detailed|threats",
  "file_ids": [1, 2, 3],
  "date_from": "2025-01-01T00:00:00",
  "date_to": "2025-12-31T23:59:59"
}

# Download report
GET /api/reports/download/{filename}
```

## 🏗️ Adding New AV Engines

The microservices architecture makes adding new engines straightforward:

### 1. Create Engine Container

```dockerfile
# Dockerfile.newengine
FROM python:3.10-slim

# Install your AV engine
RUN apt-get update && apt-get install -y your-av-engine

# Copy service script
COPY newengine_service.py .
COPY requirements.newengine.txt .
RUN pip install -r requirements.newengine.txt

EXPOSE 5000
CMD ["python", "newengine_service.py"]
```

### 2. Implement Service API

```python
# newengine_service.py
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'service': 'New Engine',
        'version': get_engine_version()
    })

@app.route('/scan', methods=['POST'])
def scan_file():
    data = request.get_json()
    file_path = data['file_path']
    
    # Implement your scanning logic
    result = scan_with_engine(file_path)
    
    return jsonify(result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

### 3. Add to Docker Compose

```yaml
# docker-compose.yml
new-engine:
  build:
    context: .
    dockerfile: Dockerfile.newengine
  volumes:
    - shared-files:/app/shared-files
  networks:
    - malware-analysis
  restart: unless-stopped
```

### 4. Register with Orchestrator

```python
# The orchestrator will automatically discover the new engine
# Or manually add via API:
POST /api/containers/add
{
  "engine_id": "newengine",
  "name": "New Engine",
  "url": "http://new-engine:5000"
}
```

## 📊 Monitoring & Maintenance

### Health Monitoring

```bash
# Check all container status
sudo docker-compose ps

# View container logs
sudo docker-compose logs [service-name]

# Monitor resource usage
sudo docker stats

# Check application health
curl http://localhost:8080/api/containers/health
```

### Database Maintenance

```bash
# Access database container
sudo docker-compose exec orchestrator python -c "
from app import get_db_connection
conn = get_db_connection()
# Run maintenance queries
"

# Backup database
sudo docker-compose exec orchestrator cp /app/data/malware_analysis.db /app/backups/
```

### Log Management

```bash
# View application logs
sudo docker-compose logs orchestrator

# View ClamAV logs  
sudo docker-compose logs clamav-scanner

# Follow logs in real-time
sudo docker-compose logs -f
```

## 🔧 Troubleshooting

### Common Issues

**🐳 Container Won't Start**
```bash
# Check container logs
sudo docker-compose logs [service-name]

# Verify port availability
netstat -tulpn | grep :8080

# Check Docker daemon
systemctl status docker
```

**🔌 Container Communication Failed**
```bash
# Test inter-container connectivity
sudo docker-compose exec orchestrator curl http://clamav-scanner:5000/health

# Check Docker network
sudo docker network inspect primal-v2_malware-analysis
```

**💾 Database Issues**
```bash
# Reinitialize database
sudo docker-compose exec orchestrator python -c "
from app import analyzer
analyzer.init_database()
"
```

**🛡️ ClamAV Issues**
```bash
# Update signatures manually
sudo docker-compose exec clamav-scanner freshclam

# Restart ClamAV daemon
sudo docker-compose restart clamav-scanner

# Check ClamAV daemon status
sudo docker-compose exec clamav-scanner ps aux | grep clam
```

### Performance Optimization

**Memory Usage**
- Increase Docker memory limit in Docker Desktop
- Adjust container resource limits in docker-compose.yml
- Monitor with `docker stats`

**Disk Space**
- Regular cleanup: `sudo docker system prune`
- Archive old analysis results
- Use tmpfs for temporary scan files

**Network Performance**
- Use local DNS resolution for containers
- Optimize shared volume configuration
- Consider dedicated Docker networks

## 🤝 Contributing

We welcome contributions! Here's how to get started:

### Code Standards

- **Python**: Follow PEP 8, use type hints
- **Docker**: Multi-stage builds, minimal base images  
- **API**: RESTful design, proper HTTP status codes
- **Documentation**: Docstrings for all functions
- **Testing**: Unit tests for critical functions

### Pull Request Process

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes with tests
4. Commit changes (`git commit -m 'Add amazing feature'`)
5. Push to branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **YARA Project**: Pattern matching engine
- **ClamAV Team**: Open-source antivirus engine
- **VirusTotal**: Multi-engine scanning API
- **Hybrid Analysis**: Dynamic analysis platform
- **MetaDefender**: OPSWAT threat detection
- **Flask Community**: Web framework
- **Docker Community**: Containerization platform

##To-Do

- ** Containerize Yara

**⚡ PRIMAL v2.0** - Empowering security researchers with scalable, containerized malware analysis capabilities.

*Built with ❤️ for the cybersecurity community*
