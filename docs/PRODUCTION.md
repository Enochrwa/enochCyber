# Production Deployment Guide for CyberWatch

This guide outlines the steps and best practices for moving the CyberWatch (eCyber) security platform into a production environment.

## 1. Environment Configuration

### Secret Management
- Never commit actual secrets (API keys, database passwords, JWT secret keys) to version control.
- Use the provided `backend/.env.example` as a template to create a `.env` file in the `backend/` directory.
- Generate a strong, unique `SECRET_KEY` for JWT token generation.

### Database
- While SQLite is used for development, **PostgreSQL** is highly recommended for production due to its concurrency support and robustness.
- Update `SQLALCHEMY_DATABASE_URL` in your `.env` file to point to your PostgreSQL instance.
- Ensure you have regular backup procedures in place for your database.

## 2. Containerization with Docker

The project includes a `Dockerfile` in the `backend/` directory and a `docker-compose.yml` in the root.

### Building and Running
```bash
docker-compose up --build -d
```
This will build the backend image and start it in detached mode.

### System Permissions
- The packet sniffer (Scapy) requires elevated privileges (root/sudo) to access network interfaces.
- When running in Docker, you may need to grant the container `NET_ADMIN` capabilities or run it in `network_mode: host`.
- **Security Warning:** Running with elevated privileges increases the attack surface. Ensure the host system is well-hardened.

## 3. Web Server & Reverse Proxy

### ASGI Server
- Use **Hypercorn** (included) or **Uvicorn** to run the FastAPI application.
- In production, it is recommended to run multiple worker processes to handle concurrent requests.

### Reverse Proxy (Nginx/Traefik)
- Always place a reverse proxy like **Nginx** in front of your FastAPI application.
- Use Nginx for:
    - **SSL/TLS Termination:** Handle HTTPS connections.
    - **Load Balancing:** Distribute traffic across multiple backend instances.
    - **Static File Serving:** Serve the built frontend assets.
    - **Buffering and Rate Limiting:** Protect the backend from bursts of traffic or DDoS attacks.

## 4. Frontend Deployment

### Building for Production
1. Navigate to the `eCyber` directory.
2. Run `npm run build`.
3. The resulting `dist/` directory contains static assets that can be served by Nginx or a CDN.

### Electron App
- If deploying as a desktop application, use `npm run package` to generate installers for target platforms.
- Ensure the production builds point to the correct production backend URL.

## 5. Monitoring and Logging

### Logging
- Logs are configured to output to the `backend/logs/` directory.
- Use a log rotation tool (like `logrotate`) to prevent logs from consuming all disk space.
- Consider using a centralized logging system (e.g., ELK stack, Graylog) for easier analysis.

### Health Checks
- The backend provides a `/api/health` endpoint. Configure your load balancer or container orchestrator (Kubernetes) to use this for health monitoring.

## 6. Security Hardening

- **Firewall:** Only expose necessary ports (e.g., 80, 443).
- **Updates:** Regularly update dependencies (Python packages and NPM modules) to patch security vulnerabilities.
- **CORS:** Restrict `BACKEND_CORS_ORIGINS` to only include your trusted frontend domains.
- **Least Privilege:** Run the application with the minimum necessary system permissions.

## 7. Scaling

- **Horizontal Scaling:** The backend can be scaled horizontally by running multiple instances behind a load balancer.
- **Socket.IO Scaling:** If using multiple backend instances, you **must** use a Redis adapter for Socket.IO to ensure events are correctly broadcasted across all nodes. Update `REDIS_URL` in your configuration.
