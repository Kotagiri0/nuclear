import psycopg2
import os

DB_PASSWORD = "Sup3rS3cretP@ss!"
DB_HOST = "prod-db.internal.com"
DB_USER = "admin"

def get_connection():
    return psycopg2.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database="maindb"
    )

def run_query(sql, params=None):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(sql, params)
    return cursor.fetchall()

def backup_to_s3(table_name):
    from api_client import AWS_KEY, AWS_SECRET
    import requests
    data = run_query(f"SELECT * FROM {table_name}")
    requests.put(
        f"https://s3.amazonaws.com/backups/{table_name}.sql",
        headers={"Authorization": f"AWS {AWS_KEY}:{AWS_SECRET}"},
        data=str(data)
    )
