# 🔬 PRIMAL v1.0 - Personal Malware Analysis Lab

**PR**ism  **I**nfosec **M**alware **A**nalysis **L**ab

A comprehensive, containerized malware analysis platform built with a microservices architecture for scalable, multi-engine static analysis.

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Docker](https://img.shields.io/badge/docker-required-blue.svg)
![Python](https://img.shields.io/badge/python-3.10-green.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## ✨ Features

### 🛡️ Multi-Engine Antivirus Scanning

* **Containerized Engines**: ClamAV running in isolated Docker container
* **Remote API Integration**: VirusTotal, Hybrid Analysis, MetaDefender
* **Extensible Architecture**: Easy addition of new AV engines
* **Real-time Results**: Live scanning with detailed threat analysis

### 🔬 Advanced Analysis Capabilities

* **Containerized YARA Service**: Dedicated YARA container with HTTP API for improved performance
* **Configurable String Extraction**: Regex patterns, API calls, suspicious keywords
* **File Type Analysis**: Magic number detection and metadata extraction
* **Hash Analysis**: MD5, SHA256 calculation and verification
* **Entropy Analysis**: Shannon entropy calculation for detecting packed/encrypted malware

### 🕵️ Threat Hunting & IOC Generation

* **KQL Query Generation**: Microsoft Defender queries for threat hunting
* **YARA Rule Creation**: Automatic rule generation from samples
* **IOC Export**: JSON, CSV, STIX, MISP formats
* **Detection Engineering**: Custom detection content creation

### 📊 Comprehensive Reporting

* **Multiple Report Types**: Summary, detailed, and threat-focused reports
* **Export Formats**: JSON, CSV, PDF-ready HTML
* **Historical Analysis**: Track analysis over time
* **Comparison Analytics**: Cross-engine result analysis

### 🧩 Microservices Architecture

* **Three-Container Design**: Orchestrator, YARA, and ClamAV services
* **Container Isolation**: Each service in dedicated container with health monitoring
* **Horizontal Scaling**: Scale individual components independently
* **Fault Tolerance**: Service failures don't affect other engines
* **Fast Startup**: Independent service initialization for improved performance

### 📦 Container Management

* **Real-time Health Monitoring**: Container status dashboard
* **Service Restart Capability**: Individual container restart functionality
* **Resource Monitoring**: Per-service resource allocation and tracking
* **Automated Health Checks**: Built-in service availability monitoring

## 🏗️ Architecture Overview

```
+-----------------------------------------------------------------------------+
¦                         PRIMAL v1.0 Architecture                           ¦
+-----------------------------------------------------------------------------¦
¦                                                                             ¦
¦  +-----------------+    +-----------------+    +-----------------+          ¦
¦  ¦  Web Interface  ¦    ¦   File Upload   ¦    ¦ Container Mgmt  ¦          ¦
¦  ¦     (Flask)     ¦    ¦   & Storage     ¦    ¦   Dashboard     ¦          ¦
¦  +-----------------+    +-----------------+    +-----------------+          ¦
¦           ¦                       ¦                       ¦                 ¦
¦  +-----------------------------------------------------------------------+  ¦
¦  ¦              Main Orchestrator Container                              ¦  ¦
¦  ¦  • Analysis Coordination & File Management                            ¦  ¦
¦  ¦  • Database Management                                                ¦  ¦
¦  ¦  • Remote API Integration (VT, HA, MD)                                ¦  ¦
¦  ¦  • Report Generation                                                  ¦  ¦
¦  ¦  • Threat Hunting & IOC Generation                                    ¦  ¦
¦  ¦  • String & Entropy Analysis                                          ¦  ¦
¦  ¦  • Container Health Monitoring                                        ¦  ¦
¦  +-----------------------------------------------------------------------+  ¦
¦           ¦                                                                 ¦
¦  +-----------------------------------------------------------------------+  ¦
¦  ¦                       Shared File Storage                             ¦  ¦
¦  +-----------------------------------------------------------------------+  ¦
¦           ¦                                                                 ¦
¦  +-----------------+    +-----------------+    +-----------------+          ¦
¦  ¦  ClamAV Service ¦    ¦  YARA Service   ¦    ¦ Future AV Engine¦          ¦
¦  ¦   (Container)   ¦    ¦   (Container)   ¦    ¦   (Container)   ¦          ¦
¦  ¦  • REST API     ¦    ¦  • HTTP API     ¦    ¦  • REST API     ¦          ¦
¦  ¦  • Auto-updates ¦    ¦  • Rule Compile ¦    ¦  • Isolated     ¦          ¦
¦  ¦  • Health Check ¦    ¦  • Independent  ¦    ¦  • Configurable ¦          ¦
¦  ¦  • Port: 5000   ¦    ¦    Startup      ¦    ¦  • Health Check ¦          ¦
¦  ¦                 ¦    ¦  • Port: 5001   ¦    ¦                 ¦          ¦
¦  +-----------------+    +-----------------+    +-----------------+          ¦
¦                                                                             ¦
+-----------------------------------------------------------------------------+
```


## 🚀 Quick Start

### Prerequisites

* **🐳 Docker & Docker Compose**: Version 20.10+ recommended
* **💻 10GB RAM**: Minimum for running all three services
* **💾 15GB Disk Space**: For containers, databases, and file storage
* **🌐 Network Access**: For remote API services (optional)

### Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/prisminfoseclabs/primal.git
   cd primal
   ```

2. **Configure Environment**
   ```bash
   # Install Docker and setup environment
   chmod +x docker_setup.sh
   chmod +x primal_control.sh
   chmod +x install_service.sh
   ./docker_setup.sh

   # Copy environment template
   cp .env.example .env
   
   # Edit configuration
   nano .env
   ```

3. **Add YARA Rules**
   ```
   Grab any rules you want from: https://github.com/InQuest/awesome-yara
   and put them in /rules - you can have nested folders here.
   The dedicated YARA container will compile these rules independently,
   improving startup performance. Rules with issues will not cause
   compilation to fail - they are handled gracefully, and you can see
   what they are in the docker logs.
   ```
   
4. **Build the Platform**
   ```bash
   # Build all three containers
   sudo docker compose build
   
   # Check service status
   sudo docker compose ps
   ```

5. **Start the Platform**
   ```bash
   # Start all services (orchestrator, yara-scanner, clamav-scanner)
   sudo docker compose up -d
   
   # Monitor startup progress
   sudo docker compose logs -f
   
   # Check service health
   sudo docker compose ps

   # ALTERNATIVELY
   sudo ./primal_control.sh start
   ```

6. **Access the Interface**

```
🌐 Web Interface: http://0.0.0.0:8080
📦 Container Health: http://0.0.0.0:8080/containers
📡 Service Status: http://0.0.0.0:8080/api/containers/health
```

## ⚙️ Configuration


Create `.env` or modify and resave the .env.example file in the project root as .env:

```bash
# Security
SECRET_KEY=your-super-secret-key-change-this-in-production

# API Keys (Optional - for remote engines)
VIRUSTOTAL_API_KEY=your_virustotal_api_key
HYBRID_ANALYSIS_API_KEY=your_hybrid_analysis_api_key  
METADEFENDER_API_KEY=your_metadefender_api_key

# Container URLs (Auto-configured)
CLAMAV_URL=http://clamav-scanner:5000
YARA_URL=http://yara-scanner:5001

# Service Configuration
YARA_PORT=5001
YARA_HOST=0.0.0.0

# Flask Environment
FLASK_ENV=production
PYTHONUNBUFFERED=1
```

### Container Resources

Adjust resource limits in `docker compose.yml`:

```yaml
# YARA Scanner (Higher memory for rule compilation)
yara-scanner:
  deploy:
    resources:
      limits:
        memory: 3G      # Higher limit for rule compilation
        cpus: '2.0'     # More CPU for YARA operations
      reservations:
        memory: 1G      # Reserved for rule compilation
        cpus: '1.0'

# ClamAV Scanner
clamav-scanner:
  deploy:
    resources:
      limits:
        memory: 2G      # Standard AV memory
        cpus: '1.0'     
      reservations:
        memory: 512M    
        cpus: '0.5'

# Orchestrator
orchestrator:
  deploy:
    resources:
      limits:
        memory: 1G      # Main application
        cpus: '1.0'     
      reservations:
        memory: 256M    
        cpus: '0.25'
```


## 🧑‍💻Usage Guide

### 🧪 Basic Analysis Workflow

1. **Upload Sample** 🗂️
2. **Automatic Analysis** 🔍
3. **Review Results** 📄
4. **Generate Intelligence** 🧠

### 🛠️ Container Service Management

Access the container management page (`/containers`) to:

- **Monitor Health**: Real-time status of all three containers
- **Restart Services**: Individual container restart capability
- **Resource Monitoring**: View memory and CPU usage per service
- **Service Logs**: Access container-specific logging
- **Health Checks**: Automated service availability monitoring

### 🛡️ Antivirus Engine Management

Access the AV management page to:

- **Configure Engines**: Enable/disable individual engines
- **Add API Keys**: Configure remote service credentials
- **Check Health**: Monitor container service status
- **Update Signatures**: Refresh AV definitions

### 🧵 YARA Rule Management

The containerized YARA service provides:

- **Independent Compilation**: Rules compile in dedicated container for faster startup
- **HTTP API Access**: RESTful interface for rule operations
- **Auto-reload**: Automatically refresh rule changes
- **Rule Validation**: Graceful handling of rule compilation errors
- **Health Monitoring**: Dedicated YARA service status tracking

### 🔡 String & Entropy Analysis

Enhanced analysis capabilities:

- **String Extraction**: Regex patterns, API calls, suspicious keywords
- **Entropy Analysis**: Shannon entropy calculation for the entire file
- **Block Analysis**: Segment-wise entropy to identify suspicious regions
- **Packed Detection**: Automatic identification of packed/encrypted content
- **Extraction Settings**: Control length limits and filters

## 📚 API Reference

### Container Management

```bash
# Check all container health
GET /api/containers/health

# Restart specific container
POST /api/containers/{container_id}/restart

# Get container service status
GET /api/rules/service-status


### File Analysis

```bash
# Upload and analyze file (includes entropy analysis)
POST /upload
Content-Type: multipart/form-data

# Get analysis results (includes entropy data)
GET /api/files/{file_id}

# Rescan with AV engines
POST /api/av/scan/{file_id}

# Check submitted analysis status
POST /api/analysis/update/{file_id}
```

### YARA Service Integration

```bash
# YARA service health (via orchestrator)
GET /api/rules/service-status

# Scan with YARA rules (containerized)
POST /api/yara/scan
{
  "file_path": "/path/to/file"
}

# Get YARA rule statistics
GET /api/yara/stats
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
# Generate analysis report (includes entropy analysis)
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

## 🧩 Adding New AV Engines

### Coming Soon

## 📈 Monitoring & Maintenance

### Health Monitoring

```bash
# Check all container status
sudo docker compose ps

# View container-specific logs
sudo docker compose logs orchestrator
sudo docker compose logs yara-scanner
sudo docker compose logs clamav-scanner

# Monitor resource usage per container
sudo docker stats

# Check application health dashboard
curl http://localhost:8080/api/containers/health

# Access container management interface
open http://localhost:8080/containers
```

### Database Maintenance

```bash
# Access database container
sudo docker compose exec orchestrator python -c "
from app import get_db_connection
conn = get_db_connection()
# Run maintenance queries
"

# Backup database
sudo docker compose exec orchestrator cp /app/data/malware_analysis.db /app/backups/
```

### Service-Specific Maintenance

```bash
# YARA service maintenance
sudo docker compose exec yara-scanner curl http://localhost:5001/health
sudo docker compose logs yara-scanner

# ClamAV service maintenance
sudo docker compose exec clamav-scanner curl http://localhost:5000/health
sudo docker compose exec clamav-scanner freshclam

# Restart individual services
sudo docker compose restart yara-scanner
sudo docker compose restart clamav-scanner
sudo docker compose restart orchestrator
```

## 🛠️ Troubleshooting

### Common Issues

**🐳 Container Won't Start**
```bash
# Check container logs for specific service
sudo docker compose logs orchestrator
sudo docker compose logs yara-scanner  
sudo docker compose logs clamav-scanner

# Verify port availability
netstat -tulpn | grep :8080  # Orchestrator
netstat -tulpn | grep :5001  # YARA
netstat -tulpn | grep :5000  # ClamAV

# Check Docker daemon
systemctl status docker
```

** 🔌 Container Communication Failed**

```bash
# Test inter-container connectivity
sudo docker compose exec orchestrator curl http://clamav-scanner:5000/health
sudo docker compose exec orchestrator curl http://yara-scanner:5001/health

# Check Docker network
sudo docker network inspect primal-v1_malware-analysis

# Verify service dependencies
sudo docker compose config
```

**🧵 YARA Service Issues**

```bash
# Check YARA rule compilation
sudo docker compose logs yara-scanner | grep -i error

# Restart YARA service independently
sudo docker compose restart yara-scanner

# Test YARA service directly
curl http://localhost:5001/health

# Check rule compilation status
sudo docker compose exec yara-scanner ls -la /app/rules
```

** 🦠 ClamAV Issues**

```bash
# Update signatures manually
sudo docker compose exec clamav-scanner freshclam

# Restart ClamAV daemon
sudo docker compose restart clamav-scanner

# Check ClamAV daemon status
sudo docker compose exec clamav-scanner ps aux | grep clam
```

** 🗄️ Database Issues**

```bash
# Reinitialize database
sudo docker compose exec orchestrator python -c "
from app import analyzer
analyzer.init_database()
"
```

### Performance Optimization

* **📈 Memory Usage**
- Increase Docker memory limit in Docker Desktop (minimum 10GB for all services)
- Adjust container resource limits in docker compose.yml
- Monitor per-service usage with `docker stats`
- YARA container needs higher memory allocation for rule compilation

* **⚡ Startup Performance**
- YARA service compiles rules independently, allowing orchestrator to start immediately
- Use `.dockerignore` to exclude unnecessary files
- Pre-compile YARA rules in container build process for production

* **💾 Disk Space**
- Regular cleanup: `sudo docker system prune`
- Archive old analysis results
- Use tmpfs for temporary scan files
- Monitor shared volume usage

* **🌐 Network Performance**
- Use local DNS resolution for containers
- Optimize shared volume configuration  
- Consider dedicated Docker networks for high-throughput scenarios

### Service Recovery

* **🤖 Automatic Recovery**
- Health checks automatically restart failed containers
- Orchestrator handles service unavailability gracefully
- Failed analyses can be re-queued when services recover

* **🔄 Manual Recovery**

```bash
# Restart all services
sudo docker compose restart

# Restart specific service
sudo docker compose restart yara-scanner

# Rebuild container if needed
sudo docker compose build yara-scanner
sudo docker compose up -d yara-scanner
```

## 🤝 Contributing

Please feel free to grab a copy and make modifications, or suggest enhancements we can add!

### Code Standards

- **Python**: Follow PEP 8, use type hints
- **Docker**: Multi-stage builds, minimal base images  
- **API**: RESTful design, proper HTTP status codes
- **Documentation**: Docstrings for all functions
- **Testing**: Unit tests for critical functions
- **Containers**: Health checks for all services

### Pull Request Process

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes with tests
4. Test with all three containers
5. Update documentation if architecture changes
6. Commit changes (`git commit -m 'Add amazing feature'`)
7. Push to branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### Development Setup

```bash
# Development with live reloading
sudo docker compose -f docker compose.dev.yml up

# Run tests
sudo docker compose exec orchestrator python -m pytest

# Check container health during development
sudo docker compose exec orchestrator curl http://yara-scanner:5001/health
```

## 📜 License

This project is licensed under the MIT License.

## 🙏 Acknowledgments

* **YARA Project** 🧵
* **ClamAV Team** 🦠
* **VirusTotal** 🛡️
* **Hybrid Analysis** 🧪
* **MetaDefender** 🔍
* **Flask Community** 🐍
* **Docker Community** 🐳
* **Claude.AI** 

## 📝 To-Do

* Add more AV engines ⚙️
* Integrate dynamic analysis 🔄
* Use ML-based detection 🧠
* Enable distributed scanning 🌐
* Build centralized API gateway 🚪

---

**🔬 PRIMAL v1.0** — Empowering security researchers with scalable, containerized malware analysis capabilities.

*Built with ❤️ for the cybersecurity community*
