# Resumatter

Resumatter is an AI-powered command-line tool that helps optimize resumes for specific job applications. It provides intelligent resume tailoring, accuracy evaluation, and job description analysis using Google's Gemini AI.

## Overview

Resumatter helps job seekers streamline the resume optimization process through automated analysis and tailoring. The tool ensures resume accuracy while maximizing relevance to target positions.

## Key Features

### Core Functionality
- **Resume Tailoring**: Intelligently adapt resumes to match specific job requirements while maintaining accuracy
- **Resume Evaluation**: Detect potential fabrications, exaggerations, or inconsistencies in tailored resumes
- **Job Description Analysis**: Assess job postings for quality, clarity, and inclusivity
- **HTTP API Server**: RESTful endpoints for integration with existing workflows

### Extra Features
- **Circuit Breaker Pattern**: Fault tolerance with per-operation failure isolation
- **Observability**: OpenTelemetry tracing and Prometheus metrics integration
- **Security**: HashiCorp Vault support for secret management
- **TLS Support**: Configurable encryption with mutual authentication
- **Rate Limiting**: Configurable request throttling and protection
- **Custom Prompts**: External file-based prompt management for flexibility

## Getting Started

### 1. Download Binary
Download the latest release from GitHub:
```bash
# Download for Linux x64 from releases page
curl -L https://github.com/ajiwo/resumatter/releases/latest/download/resumatter-linux-amd64.tar.gz -o resumatter-linux-amd64.tar.gz
tar -xzf resumatter-linux-amd64.tar.gz
chmod +x resumatter
```

### 2. Get API Key
Obtain a Google Gemini API key:
1. Visit [Google AI Studio](https://aistudio.google.com/app/apikey)
2. Create a new API key
3. Copy the key for configuration

### 3. Configure API Key
Set your API key using either method:

**Option A: Environment Variable (Recommended)**
```bash
export RESUMATTER_AI_APIKEY="your-api-key-here"
resumatter tailor examples/resume.txt examples/job.txt
```

**Option B: Configuration File**
Create `config.yaml`:
```yaml
ai:
  apiKey: "your-api-key-here"
```

### 4. Start Using
```bash
# Tailor a resume
resumatter tailor examples/resume.txt examples/job.txt --format text -o tailored.txt

# Evaluate accuracy
resumatter evaluate examples/resume.txt tailored.txt

# Analyze job description
resumatter analyze job-description.txt
```

## Installation

### Build from Source
```bash
make build
./build/resumatter --help
```

### Manual Build
```bash
go build -o ./build/resumatter ./cmd/resumatter
./build/resumatter --help
```

### Requirements
- Google Gemini API key (only required configuration)
- Go 1.24.5 or later (for building from source)

## Configuration

Resumatter uses YAML configuration files for flexible deployment. See `config.example.yaml` for comprehensive configuration options.

### Basic Configuration
```yaml
ai:
  provider: "gemini"
  apiKey: "your-api-key-here"
  model: "gemini-2.0-flash"

app:
  logLevel: "info"
  defaultFormat: "json"
```

### Custom Prompts
Load custom prompts from external files for tailored behavior:
```yaml
ai:
  tailor:
    customPrompts:
      systemPrompts:
        tailorResumeFile: "./examples/prompts/system.tailor.md"
      userPrompts:
        tailorResumeFile: "./examples/prompts/user.tailor.md"
```

## Usage

### Command Line Interface

```bash
resumatter [command]

Available Commands:
  analyze     Analyze job descriptions for quality and effectiveness
  evaluate    Evaluate tailored resumes for accuracy and consistency
  serve       Start HTTP server for API access
  tailor      Tailor resumes for specific job descriptions
  version     Display version information
```

### Resume Tailoring
Optimize a resume for a specific job posting:
```bash
resumatter tailor examples/resume.txt examples/job.txt --output tailored-resume.json
```

### Resume Evaluation
Verify accuracy of a tailored resume against the original:
```bash
resumatter evaluate examples/resume.txt tailored-resume.txt --format json
```

### Job Description Analysis
Assess job posting quality and provide improvement recommendations:
```bash
resumatter analyze examples/job.txt --output analysis-report.json
```

### HTTP Server
Start the API server for programmatic access:
```bash
resumatter serve --port 8080
```

## API Endpoints

When running in server mode, the following REST endpoints are available:

- `POST /tailor` - Tailor a resume for a job description
- `POST /evaluate` - Evaluate resume accuracy
- `POST /analyze` - Analyze job description quality
- `GET /health` - Health check endpoint
- `GET /stats` - Server statistics and metrics

## Output Formats

Resumatter supports multiple output formats:
- **JSON**: Structured data for programmatic processing
- **Text**: Human-readable plain text output
- **Markdown**: Formatted text suitable for documentation

## Examples

The `examples/` directory contains sample resumes, job descriptions, and configuration files across various industries including finance, hospitality, IT, and marketing.

## Observability

Resumatter includes comprehensive observability features:
- **Metrics**: Prometheus-compatible metrics for monitoring
- **Tracing**: OpenTelemetry distributed tracing support
- **Logging**: Structured logging with configurable levels
- **Health Checks**: Built-in health and readiness endpoints

## Security

- **API Key Management**: Secure handling of AI provider credentials
- **TLS Encryption**: Configurable HTTPS with certificate management
- **Vault Integration**: HashiCorp Vault support for secret storage
- **Rate Limiting**: Protection against abuse and resource exhaustion

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.

Copyright 2025 Amin Riza
