import sqlite3

DB_FILE = "construction.db"

try:
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    # Add contact column to employees table
    c.execute("ALTER TABLE employees ADD COLUMN contact TEXT")

    conn.commit()
    print("Successfully added contact column to employees table.")
except sqlite3.Error as e:
    print(f"Error: {str(e)}")
finally:
    if conn:
        conn.close()