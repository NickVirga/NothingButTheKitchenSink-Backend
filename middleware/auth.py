import jwt
import os
import logging
from chalice import Response
from functools import wraps

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def verify_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from app import app
        request = app.current_request
        auth_header = request.headers.get("Authorization")

        if not auth_header or not auth_header.startswith("Bearer "):
            logger.warning("Missing or invalid Authorization header.")
            return Response(
                body={"message": "Resource requires Bearer token authorization"},
                status_code=401,
                headers={"Content-Type": "application/json"}
            )

        splitBearerToken = auth_header.split(" ")

        if len(splitBearerToken) != 2:
            logger.warning("Malformed Bearer token.")
            return Response(
                body={"message": "Bearer token is malformed"},
                status_code=400,
                headers={"Content-Type": "application/json"}
            )

        bearerToken = splitBearerToken[1]

        try:
            decoded_token = jwt.decode(
                bearerToken,
                os.environ.get('JWT_ACCESS_SECRET_KEY'),
                algorithms=['HS256']
            )
            request.context['user_id'] = decoded_token.get("user_id")

        except jwt.ExpiredSignatureError:
            logger.error("Access token has expired.")
            return Response(
                body={"message": "Access token has expired."},
                status_code=401,
                headers={"Content-Type": "application/json"}
            )
        except jwt.InvalidTokenError:
            logger.error("Invalid token.")
            return Response(
                body={"message": "Invalid token."},
                status_code=400,
                headers={"Content-Type": "application/json"}
            )

        return f(*args, **kwargs)

    return decorated_function
