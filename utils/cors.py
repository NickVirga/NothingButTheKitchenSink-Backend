import os

CORS_ORIGIN = os.environ.get("CORS_ORIGIN")

def cors_headers():
    """Returns standardized CORS headers."""
    return {
        "Access-Control-Allow-Origin": CORS_ORIGIN,
        "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE",
        "Access-Control-Allow-Headers": "Authorization, Content-Type",
        "Content-Type": "application/json"
    }
