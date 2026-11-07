import sqlite3
import os

# Create the database file inside the database folder
DB_PATH = os.path.join(os.path.dirname(__file__), "shadowtrace.db")

def init_db():
    """Initializes the database and creates tables if they don't exist."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # 1. Cases Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cases (
            case_id TEXT PRIMARY KEY,
            investigator TEXT,
            created_at TEXT,
            status TEXT
        )
    ''')
    
    # 2. Evidence Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS evidence (
            evidence_id TEXT PRIMARY KEY,
            case_id TEXT,
            filename TEXT,
            sha256_hash TEXT,
            ingested_at TEXT,
            FOREIGN KEY(case_id) REFERENCES cases(case_id)
        )
    ''')
    
    conn.commit()
    conn.close()

# Initialize the database when this script is imported
init_db()

def get_db_connection():
    """Returns a connection to the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row # Allows accessing columns by name
    return conn

if __name__ == "__main__":
    print("Database initialized successfully!")