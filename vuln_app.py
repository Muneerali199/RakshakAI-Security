import sqlite3
import subprocess
import os

def get_user(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()

def render_page(name):
    return f"<html><body><h1>Welcome {name}</h1></body></html>"

api_key = "sk-abc123def456ghijklmnop"
password = "admin123"

def execute(cmd):
    os.system(cmd)

def save_file(content):
    with open("/tmp/data", "w") as f:
        f.write(content)

def verify_token(token):
    if token == "secret":
        return True
    return False
