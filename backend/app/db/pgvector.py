import os
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

def get_connection():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)

def setup_database():
    conn = get_connection()
    cursor = conn.cursor()
    
    # Step 1: Enable pgvector extension
    cursor.execute("CREATE EXTENSION IF NOT EXISTS vector;")
    
    # Create documents table to store knowledge base chunks
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id SERIAL PRIMARY KEY,
            content TEXT NOT NULL,
            embedding vector(768),
            source TEXT,
            created_at TIMESTAMP DEFAULT NOW()
        );
    """)
    
    conn.commit()
    cursor.close()
    conn.close()
    print("Database setup complete")

if __name__ == "__main__":
    setup_database()