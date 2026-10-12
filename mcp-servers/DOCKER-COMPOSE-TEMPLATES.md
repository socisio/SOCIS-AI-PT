# ─── DOCKER-COMPOSE TEMPLATE FOR NEW MCP SERVICES ───
# 
# Copy and paste one of these blocks into docker-compose.yml
# for each new MCP you want to add.
# Don't forget to update:
# 1. Container name (socis_XXX_mcp)
# 2. Port mapping (change 8100 to your port)
# 3. Command (change XXX_server.py to your server)

# ─────────────────────────────────────────────────────────
# TEMPLATE 1: LIGHTWEIGHT PYTHON MCP (Most Common)
# Use for: OWASP ZAP, Burp Suite, WAF Detection, etc.
# ─────────────────────────────────────────────────────────

  {tool_name}_mcp:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: socis_{tool_name}_mcp
    restart: unless-stopped
    command: ["python3", "{tool_name}_server.py"]
    ports:
      - "{PORT}:{PORT}"
    networks: [socis-net]
    environment:
      LOG_LEVEL: info
      # Add tool-specific env vars here
      # TOOL_API_KEY: ${TOOL_API_KEY:-}
      # TOOL_CONFIG: /config/{tool_name}.conf
    volumes:
      # Optional: Mount config files
      # - ./{tool_name}_config:/config
      # - /tmp/{tool_name}_results:/results
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:{PORT}/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 30s
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '1'
          memory: 1G
    depends_on:
      - socis_nmap_mcp  # Optional: if this tool depends on nmap


# ─────────────────────────────────────────────────────────
# TEMPLATE 2: WITH EXTERNAL SERVICE DEPENDENCY
# Use for: Tools that need databases, RPC services, etc.
# Example: Privilege escalation MCP that needs vulnerable env
# ─────────────────────────────────────────────────────────

  {tool_name}_mcp:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: socis_{tool_name}_mcp
    restart: unless-stopped
    command: ["python3", "{tool_name}_server.py"]
    ports:
      - "{PORT}:{PORT}"
    networks: [socis-net]
    environment:
      SERVICE_HOST: {service_name}
      SERVICE_PORT: {service_port}
    depends_on:
      {service_name}:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:{PORT}/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # The service this MCP depends on
  {service_name}:
    image: {image_name}
    container_name: socis_{service_name}
    restart: unless-stopped
    environment:
      # Service configuration
      SETUP: true
    volumes:
      - {service_name}_data:/data
    networks: [socis-net]
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:{service_port}/health"]
      interval: 30s
      timeout: 10s
      retries: 3


# ─────────────────────────────────────────────────────────
# TEMPLATE 3: WITH GPU SUPPORT (for heavy computation)
# Use for: Tools that benefit from GPU
# Example: AI-based vulnerability detection, fuzzing engines
# ─────────────────────────────────────────────────────────

  {tool_name}_mcp:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: socis_{tool_name}_mcp
    restart: unless-stopped
    command: ["python3", "{tool_name}_server.py"]
    ports:
      - "{PORT}:{PORT}"
    networks: [socis-net]
    environment:
      CUDA_VISIBLE_DEVICES: "0"  # Use first GPU
      LOG_LEVEL: info
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: 1
              capabilities: [gpu]
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:{PORT}/health"]
      interval: 30s
      timeout: 10s
      retries: 3


# ─────────────────────────────────────────────────────────
# REAL EXAMPLE: OWASP ZAP MCP
# ─────────────────────────────────────────────────────────

  owasp_zap_mcp:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: socis_owasp_zap_mcp
    restart: unless-stopped
    command: ["python3", "owasp_zap_server.py"]
    ports:
      - "8106:8106"
    networks: [socis-net]
    environment:
      ZAP_PORT: 8080
      ZAP_HOST: owasp_zap_api
      LOG_LEVEL: info
    depends_on:
      owasp_zap_api:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8106/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  owasp_zap_api:
    image: owasp/zap2docker-stable:latest
    container_name: socis_owasp_zap_api
    restart: unless-stopped
    ports:
      - "8080:8080"
      - "8090:8090"  # ZAP UI
    networks: [socis-net]
    environment:
      - ZAP_JAVA_OPTS=-Xmx3g
    volumes:
      - zap_data:/home/zap/.ZAP_D
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080"]
      interval: 30s
      timeout: 10s
      retries: 3


# ─────────────────────────────────────────────────────────
# VOLUMES (Add to volumes section at end of docker-compose.yml)
# ─────────────────────────────────────────────────────────

volumes:
  # ... existing volumes ...
  {tool_name}_data:
  {service_name}_data:  # If using service dependency


# ─────────────────────────────────────────────────────────
# NETWORKS (Already exists, but shown for reference)
# ─────────────────────────────────────────────────────────

networks:
  socis-net:
    driver: bridge
