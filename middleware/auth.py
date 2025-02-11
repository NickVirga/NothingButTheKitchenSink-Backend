import jwt
from chalice import Response
import os
from functools import wraps

def verify_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from app import app
        request = app.current_request
        auth_header = request.headers.get("Authorization")

        if not auth_header or not auth_header.startswith("Bearer "):
            return Response(
                body={"message": "Resource requires Bearer token authorization"},
                status_code=401,
                headers={"Content-Type": "application/json"}
            )

        splitBearerToken = auth_header.split(" ")

        if len(splitBearerToken) != 2:
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
            return Response(
                body={"message": "Access token has expired."},
                status_code=400,
                headers={"Content-Type": "application/json"}
            )
        except jwt.InvalidTokenError:
            return Response(
                body={"message": "Invalid token."},
                status_code=400,
                headers={"Content-Type": "application/json"}
            )

        return f(*args, **kwargs)

    return decorated_function
