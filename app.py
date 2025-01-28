from chalice import Chalice, Response
import bcrypt
from bcrypt import checkpw
import psycopg2
from psycopg2 import pool
from psycopg2.extras import RealDictCursor
import jwt
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
import logging

load_dotenv()

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ACCESS_TOKEN_EXPIRY = timedelta(minutes=15)
# ACCESS_TOKEN_EXPIRY = timedelta(seconds=10)
REFRESH_TOKEN_EXPIRY = timedelta(days=30)
# REFRESH_TOKEN_EXPIRY = timedelta(seconds=20)

app = Chalice(app_name='nothing-but-the-kitchen-sink-backend')

db_pool = pool.SimpleConnectionPool(
    1, 10,  # min and max connections
    dbname=os.environ.get('DB_NAME'),
    user=os.environ.get('DB_USER'),
    password=os.environ.get('DB_PASSWORD'),
    host=os.environ.get('DB_HOST'),
    port=os.environ.get('DB_PORT')
)


@app.route('/register', methods=['POST'])
def register_user():
    request = app.current_request
    body = request.json_body

    email = body.get('email')
    password = body.get('password')
    secret_key = body.get('secret_key')

    if not email or not password or not secret_key:
        return Response(
            body={"message": "Email, password, and secret key are required."},
            status_code=400,
            headers={"Content-Type": "application/json"}
        )

    if secret_key != os.environ.get("REGISTER_SECRET_KEY"):
        return Response(
            body={"message": "Error registering user."},
            status_code=401,
            headers={"Content-Type": "application/json"}
        )

    conn = None
    try:
        conn = db_pool.getconn()

        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT COUNT(*) FROM users WHERE email = %s", (email,))
            if cursor.fetchone()[0] > 0:
                return Response(
                    body={"message": "Email already registered."},
                    status_code=409,
                    headers={"Content-Type": "application/json"}
                )

        hashed_password = bcrypt.hashpw(password.encode(
            'utf-8'), bcrypt.gensalt()).decode('utf-8')
        # bcrypt.hashpw generates a bcrypt hash as a bytes object, PostgreSQL’s require strings, .decode('utf-8') converts to string

        with conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO users (email, password) VALUES (%s, %s)",
                (email, hashed_password)
            )
        conn.commit()

        return Response(
            body={"message": "User registered successfully."},
            status_code=200,
            headers={"Content-Type": "application/json"}
        )
    except Exception as e:
        logger.error(f"Error registering user: {str(e)}")
        return Response(
            body={"message": "Internal server error."},
            status_code=500,
            headers={"Content-Type": "application/json"}
        )
    finally:
        if conn:
            db_pool.putconn(conn)


@app.route('/login', methods=['POST'])
def user_login():
    request = app.current_request
    body = request.json_body

    email = body.get('email')
    password = body.get('password')

    if not email or not password:
        return Response(
            body={"message": "Email and password required for login."},
            status_code=400,
            headers={"Content-Type": "application/json"}
        )

    conn = None
    try:
        conn = db_pool.getconn()

        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                "SELECT id, password, refresh_token_version FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()

        if not user:
            return Response(
                body={"message": "Invalid email or password."},
                status_code=401,
                headers={"Content-Type": "application/json"}
            )

        hashed_password = user['password']

        if not checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
            return Response(
                body={"message": "Invalid email or password."},
                status_code=401,
                headers={"Content-Type": "application/json"}
            )

        access_token = jwt.encode(
            {
                'user_id': user['id'],
                'iat': datetime.now(timezone.utc),
                'exp': datetime.now(timezone.utc) + ACCESS_TOKEN_EXPIRY
            },
            os.environ.get('JWT_ACCESS_SECRET_KEY'),
            algorithm='HS256'
        )

        refresh_token = jwt.encode(
            {
                'user_id': user['id'],
                'refresh_token_version': user['refresh_token_version'],
                'iat': datetime.now(timezone.utc),
                'exp': datetime.now(timezone.utc) + REFRESH_TOKEN_EXPIRY
            },
            os.environ.get('JWT_REFRESH_SECRET_KEY'),
            algorithm='HS256'
        )

        return Response(
            body={"message": "User login successful.",
                  'access_token': access_token,
                  'refresh_token': refresh_token},
            status_code=200,
            headers={"Content-Type": "application/json"}
        )

    except Exception as e:
        logger.error(f"Error logging user in: {str(e)}")
        return Response(
            body={"message": "Internal server error."},
            status_code=500,
            headers={"Content-Type": "application/json"}
        )
    finally:
        if conn:
            db_pool.putconn(conn)


@app.route('/refresh',  methods=['POST'])
def refresh_token():
    request = app.current_request
    body = request.json_body

    refresh_token = body.get('refresh_token')

    if not refresh_token:
        return Response(
            body={"message": "Refresh token is required."},
            status_code=400,
            headers={"Content-Type": "application/json"}
        )

    conn = None
    try:
        decoded_token = jwt.decode(
            refresh_token,
            os.environ.get('JWT_REFRESH_SECRET_KEY'),
            algorithms=['HS256']
        )

        user_id = decoded_token.get('user_id')
        refresh_token_version = decoded_token.get('refresh_token_version')
        exp = decoded_token.get('exp')

        if user_id is None or refresh_token_version is None or exp is None:
            return Response(
                body={"message": "Invalid refresh token."},
                status_code=400,
                headers={"Content-Type": "application/json"}
            )

        exp_time = datetime.fromtimestamp(exp, tz=timezone.utc)
        if exp_time < datetime.now(timezone.utc):
            return Response(
                body={"message": "Refresh token has expired."},
                status_code=400,
                headers={"Content-Type": "application/json"}
            )

        conn = db_pool.getconn()
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT refresh_token_version FROM users WHERE id = %s",
                (decoded_token['user_id'],)
            )
            refresh_token_version = cursor.fetchone()

        if not refresh_token_version or not refresh_token_version[0] == decoded_token.get('refresh_token_version'):
            return Response(
                body={"message": "Invalid refresh token."},
                status_code=400,
                headers={"Content-Type": "application/json"}
            )

        new_access_token = jwt.encode(
            {
                'user_id': decoded_token['user_id'],
                'iat': datetime.now(timezone.utc),
                'exp': datetime.now(timezone.utc) + ACCESS_TOKEN_EXPIRY
            },
            os.environ.get('JWT_ACCESS_SECRET_KEY'),
            algorithm='HS256'
        )

        return Response(
            body={"message": "Token refreshed successfully.",
                  "access_token": new_access_token,
                  "refresh_token": refresh_token},
            status_code=200,
            headers={"Content-Type": "application/json"}
        )

    except jwt.ExpiredSignatureError:
        return Response(
            body={"message": "Refresh token has expired."},
            status_code=400,
            headers={"Content-Type": "application/json"}
        )
    except jwt.InvalidTokenError:
        return Response(
            body={"message": "Invalid refresh token."},
            status_code=400,
            headers={"Content-Type": "application/json"}
        )
    except Exception as e:
        logger.error(f"Error refreshing token: {str(e)}")
        return Response(
            body={"message": "Internal server error."},
            status_code=500,
            headers={"Content-Type": "application/json"}
        )
    finally:
        if conn:
            db_pool.putconn(conn)


@app.route('/logout', methods=['POST'])
def user_logout():
    request = app.current_request
    body = request.json_body

    refresh_token = body.get('refresh_token')

    if not refresh_token:
        return Response(
            body={"message": "Refresh token is required."},
            status_code=400,
            headers={"Content-Type": "application/json"}
        )

    conn = None
    try:
        decoded_token = jwt.decode(
            refresh_token,
            os.environ.get('JWT_REFRESH_SECRET_KEY'),
            algorithms=['HS256']
        )

        user_id = decoded_token.get('user_id')
        if user_id is None:
            return Response(
                body={"message": "User identity unknown."},
                status_code=401,
                headers={"Content-Type": "application/json"}
            )

        conn = db_pool.getconn()

        with conn.cursor() as cursor:
            cursor.execute(
                "UPDATE users SET refresh_token_version = refresh_token_version + 1 WHERE id = %s",
                (user_id,)
            )
            
        try:
            conn.commit()
        except Exception as commit_error:
            logger.error(f"Failed to commit transaction: {str(commit_error)}")
            raise

        return Response(
            body={"message": "Logged out successfully."},
            status_code=200,
            headers={"Content-Type": "application/json"}
        )

    except jwt.ExpiredSignatureError:
        return Response(
            body={"message": "Refresh token has expired."},
            status_code=400,
            headers={"Content-Type": "application/json"}
        )
    except jwt.InvalidTokenError:
        return Response(
            body={"message": "Invalid refresh token."},
            status_code=400,
            headers={"Content-Type": "application/json"}
        )
    except Exception as e:
        logger.error(f"Error logging out: {str(e)}")
        return Response(
            body={"message": "Internal server error."},
            status_code=500,
            headers={"Content-Type": "application/json"}
        )
    finally:
        if conn:
            db_pool.putconn(conn)
