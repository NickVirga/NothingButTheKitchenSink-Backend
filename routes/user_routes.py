from chalice import Response
from db.connection import db_pool
from middleware.auth import verify_token
import logging
from psycopg2.extras import RealDictCursor
from utils.cors import cors_headers

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def user_routes(app):
    @app.route('/api/user', methods=['GET'])
    @verify_token
    def get_user():
        request = app.current_request
        user_id = request.context.get('user_id')

        conn = None
        try:
            conn = db_pool.getconn()

            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(
                    """
                    SELECT id, name, last_tasks_completed_date 
                    FROM users 
                    WHERE id = %s
                    """, (user_id,))
                user = cursor.fetchone()
                
            if not user:
                return Response(
                    body={"message": "Error retrieving user data."},
                    status_code=404,
                    headers=cors_headers()
                )

            return Response(
                body={"message": "User data retrieved successfully.",
                      "user": user},
                status_code=200,
                headers=cors_headers()
            )
        except Exception as e:
            logger.error(f"Error retrieving user data: {str(e)}")
            return Response(
                body={"message": "Internal server error."},
                status_code=500,
                headers=cors_headers()
            )
        finally:
            if conn:
                db_pool.putconn(conn)
