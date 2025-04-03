from chalice import Response
from db.connection import db_pool
from middleware.auth import verify_token
from datetime import datetime
import logging
from psycopg2.extras import RealDictCursor
from utils.cors import cors_headers

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
        is_flagged = body.get('is_flagged')

        if not due_at:
            due_at = datetime.now()

        if user_id is None or description is None or is_flagged is None:
            return Response(
                body={"message": "Required fields not completed."},
                status_code=400,
                headers=cors_headers()
            )

        conn = None
        try:
            conn = db_pool.getconn()

            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(
                    "INSERT INTO tasks (user_id, description, due_at, is_flagged) "
                    "VALUES (%s, %s, %s, %s) RETURNING id, user_id, description, due_at, is_flagged",
                    (user_id, description, due_at, is_flagged)
                )
                task = cursor.fetchone()

            conn.commit()

            task['due_at'] = task['due_at'].isoformat()

            return Response(
                body={"message": "Task created successfully.",
                      "task": task},
                status_code=200,
                headers=cors_headers()
            )
        except Exception as e:
            logger.error(f"Error creating task: {str(e)}")
            return Response(
                body={"message": "Internal server error."},
                status_code=500,
                headers=cors_headers()
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
                headers=cors_headers()
            )

        conn = None
        try:
            conn = db_pool.getconn()
            with conn.cursor() as cursor:

                cursor.execute(
                    "SELECT user_id FROM tasks WHERE id = %s", (task_id,))
                result = cursor.fetchone()

                if not result:
                    return Response(
                        body={"message": "Task not found."},
                        status_code=404,
                        headers=cors_headers()
                    )

                task_owner_id = result[0]

                if task_owner_id != user_id:
                    return Response(
                        body={"message": "User unauthorized to update task."},
                        status_code=403,
                        headers=cors_headers()
                    )

                cursor.execute(
                    "UPDATE tasks SET is_flagged = %s WHERE id = %s",
                    (is_flagged, task_id)
                )
            conn.commit()

            return Response(
                body={"message": "Task flag status updated successfully."},
                status_code=200,
                headers=cors_headers()
            )
        except Exception as e:
            logger.error(f"Error updating task flag: {str(e)}")
            return Response(
                body={"message": "Internal server error."},
                status_code=500,
                headers=cors_headers()
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
                headers=cors_headers()
            )

        #         cursor.execute(
        #             "SELECT user_id FROM tasks WHERE id = %s", (task_id,))
        #         result = cursor.fetchone()

        #         if not result:
        #             return Response(
        #                 body={"message": "Task not found."},
        #                 status_code=404,
        #                 headers=cors_headers()
        #             )

        #         task_owner_id = result["user_id"]

        #         if task_owner_id != user_id:
        #             return Response(
        #                 body={"message": "User unauthorized to update task."},
        #                 status_code=403,
        #                 headers=cors_headers()
        #             )

        conn = None
        try:
            conn = db_pool.getconn()

            with conn.cursor(cursor_factory=RealDictCursor) as cursor:

                cursor.execute(
                    "SELECT user_id FROM tasks WHERE id = %s", (task_id,))
                result = cursor.fetchone()

                if not result:
                    return Response(
                        body={"message": "Task not found."},
                        status_code=404,
                        headers=cors_headers()
                    )

                task_owner_id = result["user_id"]

                print("task_owner_id", task_owner_id)

                if task_owner_id != user_id:
                    return Response(
                        body={"message": "User unauthorized to update task."},
                        status_code=403,
                        headers=cors_headers()
                    )

                completed_at = datetime.now()

                cursor.execute(
                    "UPDATE tasks SET is_complete = %s, completed_at = %s WHERE id = %s",
                    (is_complete, completed_at, task_id)
                )

                conn.commit()


            return Response(
                body={"message": "Task completion status updated successfully.", "task": {
                    "is_complete:": is_complete, "completed_at": completed_at.isoformat()}},
                status_code=200,
                headers=cors_headers()
            )
        except Exception as e:
            logger.error(f"Error updating task completion: {str(e)}")
            return Response(
                body={"message": "Internal server error."},
                status_code=500,
                headers=cors_headers()
            )
        finally:
            if conn:
                db_pool.putconn(conn)

    @app.route('/api/tasks/{task_id}', methods=['PUT'])
    @verify_token
    def update_task(task_id):
        request = app.current_request
        body = request.json_body
        user_id = request.context.get('user_id')
        description = body.get('description')
        due_at = body.get('due_at')
        is_flagged = body.get('is_flagged')

        if description is None or due_at is None or is_flagged is None:
            return Response(
                body={"message": "One or more required fields are missing."},
                status_code=400,
                headers=cors_headers()
            )

        conn = None
        try:
            conn = db_pool.getconn()
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:

                cursor.execute(
                    "SELECT user_id FROM tasks WHERE id = %s", (task_id,))
                result = cursor.fetchone()

                if not result:
                    return Response(
                        body={"message": "Task not found."},
                        status_code=404,
                        headers=cors_headers()
                    )

                task_owner_id = result["user_id"]

                if task_owner_id != user_id:
                    return Response(
                        body={"message": "User unauthorized to update task."},
                        status_code=403,
                        headers=cors_headers()
                    )

                cursor.execute(
                    """
                UPDATE tasks
                SET description = %s, due_at = %s, is_flagged = %s
                WHERE id = %s
                RETURNING id, description, is_flagged, is_complete, due_at
                """,
                    (description, due_at, is_flagged, task_id)
                )
                updated_task = cursor.fetchone()

                if updated_task and updated_task["due_at"]:
                    updated_task["due_at"] = updated_task["due_at"].isoformat()

            conn.commit()

            return Response(
                body={"message": "Task updated successfully.",
                      "task": updated_task},
                status_code=200,
                headers=cors_headers()
            )
        except Exception as e:
            logger.error(f"Error updating task: {str(e)}")
            return Response(
                body={"message": "Internal server error."},
                status_code=500,
                headers=cors_headers()
            )
        finally:
            if conn:
                db_pool.putconn(conn)

    @app.route('/api/tasks', methods=['GET'])
    @verify_token
    def get_tasks():
        request = app.current_request
        user_id = request.context.get('user_id')

        conn = None
        try:
            conn = db_pool.getconn()

            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(
                    """
                    SELECT id, description, is_flagged, is_complete, due_at, completed_at 
                    FROM tasks 
                    WHERE user_id = %s
                    """, (user_id,))
                tasks = cursor.fetchall()

                for task in tasks:
                    if task.get("due_at"):
                        task["due_at"] = task["due_at"].isoformat()
                    if task.get("completed_at"):
                        task["completed_at"] = task["completed_at"].isoformat()

            return Response(
                body={"message": "Tasks retrieved successfully.",
                      "tasks": tasks},
                status_code=200,
                headers=cors_headers()
            )
        except Exception as e:
            logger.error(f"Error retrieving tasks: {str(e)}")
            return Response(
                body={"message": "Internal server error."},
                status_code=500,
                headers=cors_headers()
            )
        finally:
            if conn:
                db_pool.putconn(conn)

    @app.route('/api/tasks/{task_id}', methods=['DELETE'])
    @verify_token
    def delete_task(task_id):
        request = app.current_request
        user_id = request.context.get('user_id')

        conn = None
        try:
            conn = db_pool.getconn()
            with conn.cursor() as cursor:

                cursor.execute(
                    "SELECT user_id FROM tasks WHERE id = %s", (task_id,))
                result = cursor.fetchone()

                if not result:
                    return Response(
                        body={"message": "Task not found."},
                        status_code=404,
                        headers=cors_headers()
                    )

                task_owner_id = result[0]

                if task_owner_id != user_id:
                    return Response(
                        body={"message": "User unauthorized to delete task."},
                        status_code=403,
                        headers=cors_headers()
                    )

                cursor.execute('DELETE FROM tasks WHERE id = %s;', (task_id,))
            conn.commit()

            return Response(
                body={"message": "Task deleted successfully."},
                status_code=200,
                headers=cors_headers()
            )
        except Exception as e:
            logger.error(f"Error deleting task: {str(e)}")
            return Response(
                body={"message": "Internal server error."},
                status_code=500,
                headers=cors_headers()
            )
        finally:
            if conn:
                db_pool.putconn(conn)
