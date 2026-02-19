#!/usr/bin/env python3
"""
Create sample SQLite database for LangChain demo
"""
import sqlite3
from pathlib import Path

db_path = Path(__file__).parent / "sample.db"

# Remove old database if exists
if db_path.exists():
    db_path.unlink()

# Create new database
conn = sqlite3.connect(str(db_path))
cursor = conn.cursor()

# Create users table
cursor.execute("""
    CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL,
        email TEXT NOT NULL,
        role TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
""")

# Create products table
cursor.execute("""
    CREATE TABLE products (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        price REAL NOT NULL,
        stock INTEGER NOT NULL,
        category TEXT
    )
""")

# Insert sample data
users_data = [
    (1, "alice", "alice@example.com", "admin"),
    (2, "bob", "bob@example.com", "user"),
    (3, "charlie", "charlie@example.com", "user"),
    (4, "diana", "diana@example.com", "moderator")
]

cursor.executemany(
    "INSERT INTO users (id, username, email, role) VALUES (?, ?, ?, ?)",
    users_data
)

products_data = [
    (1, "Laptop", 999.99, 15, "Electronics"),
    (2, "Mouse", 29.99, 50, "Electronics"),
    (3, "Desk Chair", 199.99, 8, "Furniture"),
    (4, "Monitor", 299.99, 12, "Electronics"),
    (5, "Keyboard", 79.99, 30, "Electronics")
]

cursor.executemany(
    "INSERT INTO products (id, name, price, stock, category) VALUES (?, ?, ?, ?, ?)",
    products_data
)

conn.commit()
conn.close()

print(f"[OK] Created sample database at {db_path}")
print("  Tables: users, products")
print("  Sample data loaded")
