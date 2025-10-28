#!/usr/bin/env python3
# secure_examples.py
# Example of safe parameterized queries in Python (sqlite3). Works in Termux with 'python' package.

import sqlite3

def init_db(path=":memory:"):
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT, email TEXT)")
    conn.commit()
    return conn

def insert_user(conn, username, email):
    # Safe: parameterized query (no string concatenation)
    cur = conn.cursor()
    cur.execute("INSERT INTO users (username, email) VALUES (?, ?)", (username, email))
    conn.commit()

def find_user_by_username(conn, username):
    # Safe parameterized SELECT
    cur = conn.cursor()
    cur.execute("SELECT id, username, email FROM users WHERE username = ?", (username,))
    return cur.fetchall()

if __name__ == "__main__":
    c = init_db()
    insert_user(c, "alice", "alice@example.org")
    print(find_user_by_username(c, "alice"))