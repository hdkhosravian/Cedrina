#!/usr/bin/env python3
"""Create an admin user using project database configuration."""

import sys
import os
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import psycopg2
import bcrypt
from src.core.config.settings import settings

def create_admin_user():
    """Create an admin user using project database settings."""

    # Admin user details
    ADMIN_USERNAME = "john_doe"
    ADMIN_EMAIL = "john_doe@gmail.com"
    ADMIN_PASSWORD = "Str0ngP@ssw0rd!"

    # Hash the password
    password_hash = bcrypt.hashpw(ADMIN_PASSWORD.encode('utf-8'), bcrypt.gensalt())
    
    # Connect using project settings
    conn = psycopg2.connect(
        host=settings.POSTGRES_HOST,
        port=settings.POSTGRES_PORT,
        database=settings.POSTGRES_DB,
        user=settings.POSTGRES_USER,
        password=settings.POSTGRES_PASSWORD.get_secret_value()
    )
    
    try:
        with conn.cursor() as cursor:
            # Check if admin user already exists
            cursor.execute("SELECT id FROM users WHERE username = %s", (ADMIN_USERNAME,))
            if cursor.fetchone():
                print("Admin user already exists!")
                return
            
            # Insert admin user
            cursor.execute("""
                INSERT INTO users (username, email, hashed_password, role, is_active, email_confirmed, created_at, updated_at)
                VALUES (%s, %s, %s, 'ADMIN', true, true, NOW(), NOW())
            """, (ADMIN_USERNAME, ADMIN_EMAIL, password_hash.decode('utf-8')))
            
            conn.commit()
            print("Admin user created successfully!")
            
    except Exception as e:
        print(f"Error creating admin user: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    create_admin_user() 