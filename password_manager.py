from menu import display_menu, create, find_all, find, setup_recovery, recover_password
from secret import get_secret_key, set_env_password, load_env_file
from database_manager import get_recovery_email, register_recovery_email, verify_recovery_email, send_verification_email
import sys
import os
import getpass
import re
import mysql.connector
import time

load_env_file()  # Load environment variables from .env file    

# Initialize database connection parameters
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "2004",
    "database": "password_manager",
    "autocommit": False,  # Explicit transaction control
    "connection_timeout": 30,
    "use_pure": True  # Use pure Python implementation
}

# Global connection object
connection = None
cursor = None

def establish_connection():
    """Create a new database connection with proper parameters"""
    global connection, cursor
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        cursor = connection.cursor(buffered=True)
        return True
    except mysql.connector.Error as error:
        print(f"\n[ERROR] Database connection failed: {error}")
        print("Please ensure the MySQL server is running and try again.")
        return False

def ensure_connection():
    """Check and reconnect to the database if needed"""
    global connection, cursor
    try:
        # If connection doesn't exist, establish it
        if connection is None:
            return establish_connection()
            
        # If connection exists but is not connected, reconnect
        if not connection.is_connected():
            print("\n[INFO] Database connection lost. Reconnecting...")
            try:
                connection.reconnect(attempts=3, delay=0.5)
                cursor = connection.cursor(buffered=True)
                print("[INFO] Reconnected to database")
                return True
            except mysql.connector.Error as error:
                print(f"\n[ERROR] Failed to reconnect: {error}")
                # Try to establish a fresh connection
                return establish_connection()
                
        return True
    except mysql.connector.Error as error:
        print(f"\n[ERROR] Database connection error: {error}")
        return False

# Function to close database connection properly
def close_connection():
    """Close database connection properly"""
    global connection, cursor
    try:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()
            print("\n[INFO] Database connection closed.")
    except mysql.connector.Error as error:
        print(f"\n[ERROR] Error closing connection: {error}")

def is_valid_email(email):
    """Validate email format"""
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return bool(re.match(pattern, email))

def setup_master_password():
    """Initial setup for master password and recovery email with improved handling"""
    print('=' * 50)
    print("Welcome to Password Manager 4000 - Initial Setup")
    print("Please set up your master password and recovery email")
    print('=' * 50)
    
    # Ensure database connection
    if not ensure_connection():
        print("[ERROR] Cannot continue without database connection.")
        return False
    
    # Set master password
    while True:
        new_password = getpass.getpass("Create a master password (minimum 8 characters): ")
        if not new_password:
            print("[ERROR] Password cannot be empty.")
            continue
            
        if len(new_password) < 8:
            print("[ERROR] Password must be at least 8 characters long.")
            continue
            
        confirm_password = getpass.getpass("Confirm master password: ")
        if new_password != confirm_password:
            print("[ERROR] Passwords do not match. Please try again.")
            continue
            
        # Set the password in the environment variable
        print("\n[INFO] Saving master password...")
        if set_env_password(new_password):
            print("\n[SUCCESS] Master password created successfully!")
            break
        else:
            print("[ERROR] Failed to set master password. Please try again.")
    
    # Set recovery email
    while True:
        print("\nPlease provide an email address for password recovery:")
        print("(Example: user@example.com)")
        recovery_email = input("Email: ").strip()
        
        if not recovery_email:
            print("[ERROR] Email cannot be empty.")
            continue
            
        if not is_valid_email(recovery_email):
            print("[ERROR] Invalid email format. Please enter a valid email address.")
            continue
        
        print(f"\n[INFO] Setting up recovery for: {recovery_email}")
        success, verification_code = register_recovery_email(recovery_email)
        
        if not success:
            print(f"[ERROR] Failed to set up recovery email: {verification_code}")
            retry = input("Do you want to try again? (y/n): ").strip().lower()
            if retry != 'y':
                print("[WARNING] No recovery email set up. You will not be able to reset your master password if forgotten.")
                return False
            continue
        
        # Send verification email
        print("\n[INFO] Sending verification code to your email...")
        send_verification_email(recovery_email, verification_code)
        
        print("\n[SUCCESS] A verification code has been sent to your email.")
        print("For development purposes, the code is also printed in the console output.")
        
        # Verify the email
        attempts = 0
        while attempts < 3:
            verification_input = input("Enter verification code (or 'resend' to get a new code): ").strip()
            
            if not verification_input:
                print("[ERROR] Verification code cannot be empty.")
                continue
                
            if verification_input.lower() == 'resend':
                success, verification_code = register_recovery_email(recovery_email)
                if success:
                    send_verification_email(recovery_email, verification_code)
                    print("[INFO] A new verification code has been sent.")
                continue
                
            if verify_recovery_email(recovery_email, verification_input):
                print("\n[SUCCESS] Email verified successfully!")
                print(f"You can now use {recovery_email} to recover your master password if forgotten.")
                return True
            else:
                attempts += 1
                remaining = 3 - attempts
                if remaining > 0:
                    print(f"[ERROR] Invalid code. {remaining} attempt{'s' if remaining > 1 else ''} remaining.")
                else:
                    print("[ERROR] Too many failed attempts.")
                    print("[WARNING] Email verification failed. You will not be able to reset your master password if forgotten.")
                    return False
    
    return False

def start_password_manager():
    """Start the password manager and authenticate user with improved handling"""
    # Establish initial database connection
    if not establish_connection():
        print("[ERROR] Failed to connect to database on startup.")
        print("Please check your database connection and try again.")
        sys.exit(1)
        
    try:
        # Check if this is the first run (no master password set)
        env_password = os.getenv("PM_MASTER_PASSWORD")
        recovery_email = get_recovery_email()
        
        # If no environment password and using default, prompt setup
        if not env_password and get_secret_key() == "knjr2004":
            if not setup_master_password():
                print("\n[WARNING] Setup incomplete. Using default configuration.")
        
        print('\n' + '=' * 50)
        print("PASSWORD MANAGER 4000 - COMMAND LINE INTERFACE")
        print("Your secure password management solution")
        print('=' * 50)
        
        # Before asking for the master password, offer forgot password option
        print("1. Login with master password")
        print("2. I forgot my master password")
        login_choice = input("Choice: ").strip()
        
        if login_choice == "2":
            # Handle forgot password flow
            recover_password()
            return  # Exit after recovery attempt
        
        # Get master password
        max_attempts = 3
        attempts = 0
        
        while attempts < max_attempts:
            master_password = getpass.getpass("Please provide the master password to start using password_manager4000: ")
            
            # Check if master password is correct
            if master_password == get_secret_key():
                print("[SUCCESS] Authentication successful!")
                run_main_menu()
                break
            else:
                attempts += 1
                remaining = max_attempts - attempts
                if remaining > 0:
                    print(f"[ERROR] Authentication failed. Incorrect master password. {remaining} attempt{'s' if remaining > 1 else ''} remaining.")
                else:
                    print("[ERROR] Too many failed attempts. For security reasons, the application will now exit.")
                    sys.exit(1)
    finally:
        # Ensure connection is properly closed when exiting
        close_connection()
    
def run_main_menu():
    """Run the main menu loop after successful authentication"""
    try:
        while True:
            choice = display_menu()
            if choice == "1":
                create()
            elif choice == "2":
                find_all()
            elif choice == "3":
                find()
            elif choice == "4":
                setup_recovery()
            elif choice == "5":
                recover_password()
            elif choice.lower() == "q":
                print("Exiting password manager. Goodbye!")
                break
            else:
                print("Invalid choice. Please try again.")
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred: {e}")
        print("The application will now exit.")
        sys.exit(1)

if __name__ == "__main__":
    start_password_manager()
