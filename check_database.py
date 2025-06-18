import sqlite3

# Update this path based on your SQLALCHEMY_DATABASE_URI from .env
db_path = 'sqlite:///construction.db'  # Adjust this to match your database file path

conn = None  # Initialize conn outside the try block to avoid NameError in finally
try:
    # Connect to the database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Query the schema of the users table
    cursor.execute("PRAGMA table_info(users);")
    columns = cursor.fetchall()

    # Print the column information
    print("Columns in users table:")
    for column in columns:
        print(column)

except sqlite3.Error as e:
    print(f"Database error: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
finally:
    # Ensure the connection is closed, even if an error occurred
    if conn:
        conn.close()
        print("Database connection closed.")