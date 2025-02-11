from chalice import Response
from db.connection import db_pool
from middleware.auth import verify_token
from datetime import datetime
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def task_routes(app):
    @app.route('/api/tasks', methods=['POST'])
    @verify_token
    def create_task():
        request = app.current_request
        body = request.json_body
        user_id = request.context.get('user_id')
        description = body.get('description')
        due_at = body.get('due_at')
        print("pass")

        if not due_at:
            due_at = datetime.now()

        if user_id is None or description is None:
            return Response(
                body={"message": "Required fields not completed."},
                status_code=400,
                headers={"Content-Type": "application/json"}
            )

        conn = None
        try:
            conn = db_pool.getconn()

            with conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO tasks (user_id, description, due_at) VALUES (%s, %s, %s)",
                    (user_id, description, due_at)
                )
            conn.commit()

            return Response(
                body={"message": "Task created successfully."},
                status_code=200,
                headers={"Content-Type": "application/json"}
            )
        except Exception as e:
            logger.error(f"Error creating task: {str(e)}")
            return Response(
                body={"message": "Internal server error."},
                status_code=500,
                headers={"Content-Type": "application/json"}
            )
        finally:
            if conn:
                db_pool.putconn(conn)

    @app.route('/api/tasks/{task_id}/flag', methods=['PATCH'])
    @verify_token
    def update_task_flag(task_id):
        request = app.current_request
        body = request.json_body
        user_id = request.context.get('user_id')
        is_flagged = body.get('is_flagged')

        if is_flagged is None:
            return Response(
                body={"message": "Flag status is required."},
                status_code=400,
                headers={"Content-Type": "application/json"}
            )

        conn = None
        try:
            conn = db_pool.getconn()
            with conn.cursor() as cursor:
                
                cursor.execute("SELECT user_id FROM tasks WHERE id = %s", (task_id,))
                result = cursor.fetchone()
                
                if not result:
                    return Response(
                        body={"message": "Task not found."},
                        status_code=404,
                        headers={"Content-Type": "application/json"}
                    )
                
                task_owner_id = result[0] 

                if task_owner_id != user_id:
                    return Response(
                        body={"message": "User unauthorized to update task."},
                        status_code=403,
                        headers={"Content-Type": "application/json"}
                    )

                cursor.execute(
                    "UPDATE tasks SET is_flagged = %s WHERE id = %s",
                    (is_flagged, task_id)
                )
            conn.commit()

            return Response(
                body={"message": "Task flag status updated successfully."},
                status_code=200,
                headers={"Content-Type": "application/json"}
            )
        except Exception as e:
            logger.error(f"Error updating task flag: {str(e)}")
            return Response(
                body={"message": "Internal server error."},
                status_code=500,
                headers={"Content-Type": "application/json"}
            )
        finally:
            if conn:
                db_pool.putconn(conn)
                
    @app.route('/api/tasks/{task_id}/complete', methods=['PATCH'])
    @verify_token
    def update_task_completion(task_id):
        request = app.current_request
        body = request.json_body
        user_id = request.context.get('user_id')
        is_complete = body.get('is_complete')

        if is_complete is None:
            return Response(
                body={"message": "Completion status is required."},
                status_code=400,
                headers={"Content-Type": "application/json"}
            )

        conn = None
        try:
            conn = db_pool.getconn()
            with conn.cursor() as cursor:
                
                cursor.execute("SELECT user_id FROM tasks WHERE id = %s", (task_id,))
                result = cursor.fetchone()
                
                if not result:
                    return Response(
                        body={"message": "Task not found."},
                        status_code=404,
                        headers={"Content-Type": "application/json"}
                    )
                
                task_owner_id = result[0] 

                if task_owner_id != user_id:
                    return Response(
                        body={"message": "User unauthorized to update task."},
                        status_code=403,
                        headers={"Content-Type": "application/json"}
                    )

                cursor.execute(
                    "UPDATE tasks SET is_complete = %s WHERE id = %s",
                    (is_complete, task_id)
                )
            conn.commit()

            return Response(
                body={"message": "Task completion status updated successfully."},
                status_code=200,
                headers={"Content-Type": "application/json"}
            )
        except Exception as e:
            logger.error(f"Error updating task completion: {str(e)}")
            return Response(
                body={"message": "Internal server error."},
                status_code=500,
                headers={"Content-Type": "application/json"}
            )
        finally:
            if conn:
                db_pool.putconn(conn)
