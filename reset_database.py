import mysql.connector
import os
from secret import load_env_file

load_env_file()  # Load environment variables from .env file    
def reset_database():
    try:
        # Connect to the database
        connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password="2004",
            database="password_manager"
        )
        cursor = connection.cursor()
        
        # Delete all data from tables but keep the structure
        print("Clearing database tables...")
        
        # Drop recovery table if it exists
        cursor.execute("DROP TABLE IF EXISTS master_recovery")
        
        # Delete all credentials
        cursor.execute("DELETE FROM credentials")
        
        # Create recovery_email table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS recovery_email (
            id INT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(255) NOT NULL,
            verified BOOLEAN DEFAULT FALSE,
            verification_code VARCHAR(64),
            code_expiry TIMESTAMP NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        # Commit the changes
        connection.commit()
        
        print("Database reset successfully!")
        print("All credentials and recovery information have been deleted.")
        print("Ready for fresh setup with email-based recovery.")
        
    except mysql.connector.Error as error:
        print(f"Error resetting database: {error}")
    finally:
        if connection:
            cursor.close()
            connection.close()

if __name__ == "__main__":
    confirm = input("WARNING: This will delete ALL passwords and recovery information. Continue? (yes/no): ")
    if confirm.lower() == "yes":
        reset_database()
    else:
        print("Database reset cancelled.") 