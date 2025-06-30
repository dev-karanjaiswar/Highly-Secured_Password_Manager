from hash_maker import password
import pyperclip
from database_manager import store_passwords, find_users, find_password, secure_copy_to_clipboard
from database_manager import get_recovery_email, register_recovery_email, verify_recovery_email, send_verification_email
from database_manager import initiate_password_reset, reset_master_password, send_reset_email, change_master_password_with_reencryption
from secret import set_env_password, get_secret_key
import sys
import getpass
import os
import re
import mysql.connector
import time
from secret import load_env_file

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

def display_menu():
    print('-'*30)
    print(('-'*13) + 'Menu'+ ('-' *13))
    print('1. Create new password')
    print('2. Find all sites and apps connected to an email')
    print('3. Find a password for a site or app')
    print('4. Setup password recovery email')
    print('5. Recover master password')
    print('Q. Exit')
    print('-'*30)
    
    choice = input(': ').strip().lower()
    return choice

def create():
    print('\n' + '='*50)
    print("CREATE NEW PASSWORD")
    print('='*50)
    
    # Ensure database connection before proceeding
    if not ensure_connection():
        print("[ERROR] Cannot continue without database connection.")
        input("\nPress Enter to return to the main menu...")
        return
        
    print('Please provide the name of the site or app you want to generate a password for: ')
    app_name = input().strip()
    
    if not app_name:
        print("[ERROR] App name cannot be empty.")
        input("\nPress Enter to return to the main menu...")
        return
    
    # Option to use auto-generated password or custom password
    print('\nDo you want to:')
    print('1. Generate a secure password')
    print('2. Use your own custom password')
    pwd_choice = input(': ').strip()
    
    if pwd_choice == '1':
        print('Please provide a simple seed password for generation: ')
        plaintext = getpass.getpass("Seed password (hidden): ")
        if not plaintext:
            print("[ERROR] Seed password cannot be empty.")
            input("\nPress Enter to return to the main menu...")
            return
            
        # Generate a secure password based on the user's input
        generated_password = password(plaintext, app_name, 12)
        final_password = generated_password
        print(f'\nSecure password has been generated and will be copied to clipboard')
    else:
        # Use getpass for secure password entry
        final_password = getpass.getpass('Enter your custom password (hidden): ')
        if not final_password:
            print("[ERROR] Password cannot be empty.")
            input("\nPress Enter to return to the main menu...")
            return
    
    # Copy the password to clipboard using the secure function
    #secure_copy_to_clipboard(final_password) edited here 
    
    print('-'*50)
    #print('✓ Your password has been copied to your clipboard')
    print('✓ This password will be stored securely in encrypted format')
    print('✓ You will need your master password to access it later')
    print('-'*50)
    
    # Validate email
    while True:
        user_email = input('Please provide a user email for this app or site: ').strip()
        if not user_email:
            print("[ERROR] Email cannot be empty.")
            continue
            
        if not is_valid_email(user_email):
            print("[ERROR] Invalid email format. Please use format: user@example.com")
            continue
        break
    
    username = input('Please provide a username for this app or site (if applicable): ').strip()
    if username == '':
        username = None
        
    while True:
        url = input('Please paste the URL to the site that you are creating the password for: ').strip()
        if not url:
            print("[ERROR] URL cannot be empty.")
            continue
            
        if not is_valid_url(url):
            print("[ERROR] Invalid URL format. Please enter a valid URL.")
            continue
        break
    
    # Store the actual password (will be encrypted in the database_manager)
    try:
        store_passwords(final_password, user_email, username, url, app_name)
        print("\n[SUCCESS] Password stored successfully! You can retrieve it later using option 3 from the main menu.")
    except Exception as e:
        print(f"\n[ERROR] Failed to store password: {e}")
    
    input("\nPress Enter to return to the main menu...")

def find():
    print('\n' + '='*50)
    print("FIND PASSWORD")
    print('='*50)
    
    # Ensure database connection before proceeding
    if not ensure_connection():
        print("[ERROR] Cannot continue without database connection.")
        input("\nPress Enter to return to the main menu...")
        return
        
    print('Please provide the name of the site or app you want to find the password for:')
    app_name = input().strip()
    
    if not app_name:
        print("[ERROR] App name cannot be empty.")
        input("\nPress Enter to return to the main menu...")
        return
    
    print("\nNote: If you have multiple accounts for this site, you'll be asked to select which email to use.")
    print("Also You will need to verify your master password to access encrypted passwords.")
    find_password(app_name)
    
    input("\nPress Enter to return to the main menu...")

def find_all():
    print('\n' + '='*50)
    print("FIND ACCOUNTS BY EMAIL")
    print('='*50)
    
    # Ensure database connection before proceeding
    if not ensure_connection():
        print("[ERROR] Cannot continue without database connection.")
        input("\nPress Enter to return to the main menu...")
        return
        
    print('Please provide the email that you want to find accounts for: ')
    user_email = getpass.getpass("Email: ").strip()
    
    if not user_email:
        print("[ERROR] Email cannot be empty.")
        input("\nPress Enter to return to the main menu...")
        return
        
    if not is_valid_email(user_email):
        print("[ERROR] Invalid email format. Please use format: user@example.com")
        input("\nPress Enter to return to the main menu...")
        return
    
    print("\nNote: If encrypted passwords are found, you will need to verify your master password to access them.")
    find_users(user_email)
    
    input("\nPress Enter to return to the main menu...")

# Validation functions
def is_valid_email(email):
    """Validate email format"""
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return bool(re.match(pattern, email))

def is_valid_url(url):
    """Validate URL format"""
    pattern = r'^(https?:\/\/)?(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)$'
    return bool(re.match(pattern, url))

def setup_recovery():
    """Set up email-based recovery with improved handling"""
    print("\n" + "-" * 50)
    print("SETUP PASSWORD RECOVERY EMAIL")
    print("-" * 50)
    
    # Ensure database connection before proceeding
    if not ensure_connection():
        print("[ERROR] Cannot continue without database connection.")
        input("\nPress Enter to return to the main menu...")
        return
    
    # Check if recovery email is already set up
    current_recovery_email = get_recovery_email()
    email_change_active = False
    
    if current_recovery_email:
        print(f"Recovery email is already set up: {current_recovery_email}")
        change = input("Do you want to change your recovery email? (y/n): ").strip().lower()
        if change != 'y':
            return
        email_change_active = True
    
    # Set recovery email
    while True:
        print("\nPlease provide an email address for password recovery:")
        print("(Example: user@example.com)")
        email = input("Email: ").strip()
        
        if not email:
            print("[ERROR] Please enter an email address.")
            continue
        
        if not is_valid_email(email):
            print("[ERROR] Invalid email format. Please enter a valid email address.")
            continue
        
        print(f"\n[INFO] Setting up recovery for: {email}")
        success, verification_code = register_recovery_email(email)
        
        if not success:
            print(f"[ERROR] Failed to set up recovery email: {verification_code}")
            retry = input("Do you want to try again? (y/n): ").strip().lower()
            if retry != 'y':
                return
            continue
        
        # Send verification email
        print("\n[INFO] Sending verification code to your email...")
        send_verification_email(email, verification_code)
        
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
                success, verification_code = register_recovery_email(email)
                if success:
                    send_verification_email(email, verification_code)
                    print("[INFO] A new verification code has been sent.")
                continue
                
            if verify_recovery_email(email, verification_input):
                print("\n[SUCCESS] Email verified successfully!")
                print(f"You can now use {email} to recover your master password if forgotten.")
                return
            else:
                attempts += 1
                remaining = 3 - attempts
                if remaining > 0:
                    print(f"[ERROR] Invalid code. {remaining} attempt{'s' if remaining > 1 else ''} remaining.")
                else:
                    print("[ERROR] Too many failed attempts.")
                    return
        
        # If we get here, verification failed
        print("[ERROR] Email verification failed.")
        retry = input("Do you want to try again with a different email? (y/n): ").strip().lower()
        if retry != 'y':
            return

def recover_password():
    """Recover master password via email with improved handling"""
    print("\n" + "-" * 50)
    print("MASTER PASSWORD RECOVERY")
    print("-" * 50)
    
    # Ensure database connection before proceeding
    if not ensure_connection():
        print("[ERROR] Cannot continue without database connection.")
        input("\nPress Enter to return to the main menu...")
        return
    
    # Check if recovery email is set up
    recovery_email = get_recovery_email()
    if not recovery_email:
        print("[INFO] Password recovery has not been set up for this account.")
        print("Please set up a recovery email first.")
        setup = input("Would you like to set up password recovery now? (y/n): ").strip().lower()
        if setup == 'y':
            setup_recovery()
        return
    
    print(f"[INFO] Recovery email: {recovery_email}")
    confirm = input("Send password reset code to this email? (y/n): ").strip().lower()
    
    if confirm != 'y':
        return
    
    # Initiate password reset
    print("\n[INFO] Initiating password reset...")
    success, reset_token = initiate_password_reset(recovery_email)
    
    if not success:
        print(f"[ERROR] Failed to initiate password reset: {reset_token}")
        return
    
    # Send reset email
    print("\n[INFO] Sending reset code to your email...")
    send_reset_email(recovery_email, reset_token)
    
    print("\n[SUCCESS] A reset code has been sent to your email.")
    print("For development purposes, the code is also printed in the console output.")
    
    # Verify the reset token
    attempts = 0
    while attempts < 3:
        token_input = input("Enter reset code (or 'resend' to get a new code): ").strip()
        
        if not token_input:
            print("[ERROR] Reset code cannot be empty.")
            continue
            
        if token_input.lower() == 'resend':
            success, reset_token = initiate_password_reset(recovery_email)
            if success:
                send_reset_email(recovery_email, reset_token)
                print("[INFO] A new reset code has been sent.")
            continue
        
        # If token is correct, set new password
        if token_input == reset_token:
            print("\n[SUCCESS] Reset code verified. Please set a new master password.")
            
            while True:
                new_password = getpass.getpass("New master password (minimum 8 characters): ")
                if not new_password:
                    print("[ERROR] Password cannot be empty.")
                    continue
                    
                if len(new_password) < 8:
                    print("[ERROR] Password must be at least 8 characters long.")
                    continue
                    
                confirm_password = getpass.getpass("Confirm new master password: ")
                if new_password != confirm_password:
                    print("[ERROR] Passwords do not match. Please try again.")
                    continue
                
                # Reset the master password
                print("\n[INFO] Resetting master password and re-encrypting stored passwords...")
                print("[INFO] This may take a moment depending on how many passwords you have stored.")
                
                # Confirm the process with the user
                confirm = input("Continue with password reset and re-encryption? (y/n): ").strip().lower()
                if confirm != 'y':
                    print("[INFO] Password reset cancelled.")
                    return
                
                # Get the old master password for re-encryption
                old_password = get_secret_key()
                
                success, message = change_master_password_with_reencryption(new_password, old_password)
                
                if success:
                    print("\n" + "=" * 50)
                    print("MASTER PASSWORD RESET SUCCESSFULLY")
                    print("=" * 50)
                    print(message)
                    print("Please restart the application to use your new password.")
                    print("=" * 50)
                    sys.exit(0)
                else:
                    print(f"[ERROR] Failed to reset master password: {message}")
                    print("[INFO] Please try again later.")
                    return
        else:
            attempts += 1
            remaining = 3 - attempts
            if remaining > 0:
                print(f"[ERROR] Invalid reset code. {remaining} attempt{'s' if remaining > 1 else ''} remaining.")
            else:
                print("[ERROR] Too many failed attempts. Password reset cancelled.")
                return
    
    print("[ERROR] Password reset failed. Please try again later.")

# Run the menu when the script starts
if __name__ == "__main__":
    print("\n" + "=" * 50)
    print("PASSWORD MANAGER 4000 - COMMAND LINE INTERFACE")
    print("=" * 50)
    
    # Establish initial database connection
    if not establish_connection():
        print("[ERROR] Failed to connect to database on startup.")
        print("Please check your database connection and try again.")
        sys.exit(1)
    
    try:
        while True:
            choice = display_menu()
            if choice == '1':
                create()
            elif choice == '2':
                find_all()
            elif choice == '3':
                find()
            elif choice == '4':
                setup_recovery()
            elif choice == '5':
                recover_password()
            elif choice.lower() == 'q':
                print("Exiting password manager. Goodbye!")
                break
            else:
                print("Invalid choice. Please try again.")
    finally:
        # Ensure connection is properly closed when exiting
        close_connection()
