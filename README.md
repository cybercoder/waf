# WAF Sidecar

A high-performance Web Application Firewall (WAF) sidecar implementation using Gin, Redis, and Coraza. This service acts as a security layer that can be deployed alongside your applications to protect against various web attacks.

## Features

- Dynamic WAF rule management using Redis
- Profile-based WAF configurations
- In-memory caching for improved performance
- RESTful API endpoints for management
- Built with enterprise-grade components:
  - [Gin](https://github.com/gin-gonic/gin) - High-performance HTTP web framework
  - [Coraza](https://github.com/corazawaf/coraza) - Web Application Firewall library
  - [Redis](https://redis.io/) - For rule storage and management

## Prerequisites

- Go 1.19 or higher
- Redis server running on localhost:6379
- Docker (optional, for containerized deployment)

## Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   go mod download
   ```
3. Build the project:
   ```bash
   go build -o waf
   ```

## Configuration

The WAF sidecar can be configured through Redis. Rules are stored with the key pattern `WAF_RULES:{profile_name}`.

### Default Configuration

By default, the service:
- Listens on port 3000
- Connects to Redis at localhost:6379
- Uses "default" as the fallback profile

## API Endpoints

### Health Check
```
GET /health
```
Returns "OK" if the service is running.

### WAF Pre-Check
```
POST /pre
```
Performs WAF rule validation on incoming requests.

Headers:
- `X-WAF-Profile`: (Optional) Specify which WAF profile to use
- `X-Client-IP`: Client IP address for logging

### Remove WAF Profile
```
GET /remove/:profile
```
Removes a WAF profile from the in-memory cache.

## Usage

1. Start the WAF sidecar:
   ```bash
   ./waf
   ```

2. Configure your application to send requests through the WAF sidecar:
   ```bash
   curl -X POST \
        -H "X-WAF-Profile: custom_profile" \
        -H "Content-Type: application/json" \
        http://localhost:3000/pre
   ```

## Rule Management

WAF rules are stored in Redis using the following format:
```
Key: WAF_RULES:{profile_name}
Value: Coraza WAF rules in string format
```

Example of setting rules in Redis:
```bash
redis-cli SET "WAF_RULES:default" "SecRuleEngine On\nSecRule REQUEST_URI \"@contains admin\" \"deny,status:403\""
```

## Performance Considerations

- Rules are cached in memory using sync.Map for optimal performance
- Profile-based caching allows for different rule sets per application/endpoint
- Redis is only accessed when rules are not found in the cache

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
