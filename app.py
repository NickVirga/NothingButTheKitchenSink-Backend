from chalice import Chalice
from routes.auth_routes import register_routes
from routes.task_routes import task_routes

app = Chalice(app_name='nothing-but-the-kitchen-sink-backend')

register_routes(app)
task_routes(app)
