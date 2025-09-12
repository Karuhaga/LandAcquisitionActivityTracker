import pyodbc
from config import DATABASE_CONFIG


def get_db_connection():
    conn_str = (
        f"DRIVER={{ODBC Driver 17 for SQL Server}};"
        f"SERVER={DATABASE_CONFIG['SERVER']};"
        f"DATABASE={DATABASE_CONFIG['DATABASE']};"
        f"UID={DATABASE_CONFIG['USERNAME']};"
        f"PWD={DATABASE_CONFIG['PASSWORD']};"
        f"Trusted_Connection=no;"
    )

    try:
        conn = pyodbc.connect(conn_str)
        return conn
    except pyodbc.Error as e:
        print("Database connection error:", e)
        return None
