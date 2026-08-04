# Security Policy

## Supported Versions

Currently, only the `main` branch is receiving active security updates.

## Reporting a Vulnerability

If you discover a security vulnerability within this project, please DO NOT open a public issue. 
Instead, send an email to the security team (placeholder: security@example.com).

## Architecture Security Notes
Because this system orchestrates vulnerability scanners:
1. It handles highly sensitive data (open ports, discovered vulnerabilities, credentials).
2. The Database (PostgreSQL) and Object Storage (MinIO) must be heavily isolated from public access.
3. Scanner Agents should run in network-isolated environments and only communicate outbound to the Control Plane API.
