from fastapi import Request, Response
from datetime import datetime
import asyncio

# A simple in-memory buffer for logs
# In production, this would be Kafka or RabbitMQ
LOG_BUFFER = []

async def capture_request(request: Request, response: Response):
    """
    Captures request metadata for the Sentinel Engine.
    Non-blocking to ensure API performance.
    """
    # Extract client IP (check X-Forwarded-For first for simulated attackers)
    x_forwarded_for = request.headers.get("X-Forwarded-For")
    if x_forwarded_for:
        client_host = x_forwarded_for.split(",")[0].strip()
    else:
        client_host = request.client.host if request.client else "unknown"
    
    entry = {
        "timestamp": datetime.now().isoformat(),
        "method": request.method,
        "path": request.url.path,
        "status_code": response.status_code,
        "client_ip": client_host,
        "user_agent": request.headers.get("user-agent", "unknown"),
        # In a real app, we'd extract the user ID from the JWT token here
        "user_id": request.headers.get("x-user-id", "anonymous")
    }
    
    LOG_BUFFER.append(entry)
    
    # Keep buffer size manageable for this proto
    if len(LOG_BUFFER) > 10000:
        LOG_BUFFER.pop(0)

def get_latest_logs(limit: int = 50):
    return LOG_BUFFER[-limit:]
