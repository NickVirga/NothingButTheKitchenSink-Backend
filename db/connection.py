import os
from psycopg2 import pool
from dotenv import load_dotenv

load_dotenv()

db_pool = pool.SimpleConnectionPool(
    1, 10,  # min and max connections
    dbname=os.getenv('DB_NAME'),
    user=os.getenv('DB_USER'),
    password=os.getenv('DB_PASSWORD'),
    host=os.getenv('DB_HOST'),
    port=os.getenv('DB_PORT')
)
