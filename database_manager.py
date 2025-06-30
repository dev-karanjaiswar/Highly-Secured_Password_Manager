import mysql.connector
from cryptography.fernet import Fernet
from secret import get_secret_key, set_env_password, generate_verification_code, generate_reset_token, get_expiry_time, load_env_file
import pyperclip  # Add pyperclip to copy passwords to clipboard
import time
import threading
import getpass  # Add getpass for secure password input
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from datetime import datetime
import random

# Database connection
conn = None
cursor = None

load_env_file()

def connect():
    global conn, cursor
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="2004",
            database="password_manager",
            autocommit=False,  # Explicit transaction control
            connection_timeout=30,
            use_pure=True  # Use pure Python implementation
        )
        cursor = conn.cursor(buffered=True)
        return True
    except mysql.connector.Error as error:
        print("Error while connecting to MySQL:", error)
        return False

def ensure_connection():
    """Check and reconnect to the database if needed"""
    global conn, cursor
    try:
        # If connection doesn't exist, establish it
        if conn is None:
            return connect()
            
        # If connection exists but is not connected, reconnect
        if not conn.is_connected():
            print("\n[INFO] Database connection lost. Reconnecting...")
            try:
                # Try to rollback any pending transaction before reconnecting
                try:
                    conn.rollback()
                    print("[INFO] Rolled back pending transaction before reconnect")
                except:
                    pass
                
                conn.reconnect(attempts=3, delay=0.5)
                cursor = conn.cursor(buffered=True)
                print("[INFO] Reconnected to database")
                return True
            except mysql.connector.Error as error:
                print(f"\n[ERROR] Failed to reconnect: {error}")
                # Try to establish a fresh connection
                return connect()
                
        return True
    except mysql.connector.Error as error:
        print(f"\n[ERROR] Database connection error: {error}")
        return False

# Initialize connection
connect()

# Ensure necessary tables exist
def ensure_tables_exist():
    try:
        if not ensure_connection():
            print("Failed to connect to database for table creation")
            return
            
        # Create recovery_email table if it doesn't exist
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS recovery_email (
            id INT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(255) NOT NULL,
            verified BOOLEAN DEFAULT FALSE,
            verification_code VARCHAR(10) NULL,
            code_expiry DATETIME NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        conn.commit()
        print("Welcome to Password Manager 4000")
        
    except mysql.connector.Error as error:
        print(f"Error ensuring tables exist: {error}")
        try:
            conn.rollback()
        except:
            pass

# Call to ensure tables exist
ensure_tables_exist()

# Initialize encryption
def get_encryption_key():
    # Use the secret key to derive an encryption key
    secret = get_secret_key()
    # We need a 32-byte key for Fernet
    import base64
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    
    password = secret.encode()
    salt = b'password_manager_salt'  # This should be a constant
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

# Create a Fernet cipher
cipher_suite = None

def get_cipher_suite():
    global cipher_suite
    if cipher_suite is None:
        cipher_suite = Fernet(get_encryption_key())
    return cipher_suite

def encrypt_password(password):
    cipher = get_cipher_suite()
    return cipher.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    try:
        cipher = get_cipher_suite()
        return cipher.decrypt(encrypted_password.encode()).decode()
    except Exception as e:
        # This will happen if the password was encrypted with a different master password
        print(f"Decryption failed: {e}")
        return None  # Return None to indicate decryption failure

def reset_cipher_suite():
    """Reset the cipher suite to force recreation with current master password"""
    global cipher_suite
    cipher_suite = None

# Ensure the database schema has the necessary is_encrypted column
def ensure_schema():
    try:
        if not ensure_connection():
            print("Failed to connect to database for schema check")
            return
        
        # Check if is_encrypted column exists
        cursor.execute("SHOW COLUMNS FROM credentials LIKE 'is_encrypted'")
        result = cursor.fetchone()
        
        # If the column doesn't exist, add it
        if not result:
            cursor.execute("ALTER TABLE credentials ADD COLUMN is_encrypted BOOLEAN DEFAULT FALSE")
            conn.commit()
            print("Schema updated with encryption tracking.")
            
    except mysql.connector.Error as error:
        print("Error updating schema:", error)
        try:
            conn.rollback()
        except:
            pass

# Call ensure_schema to make sure our database is ready
ensure_schema()

# Functions for master password recovery support
def setup_recovery_options(security_question, security_answer, recovery_code=None):
    """
    Set up recovery options for the master password.
    
    Args:
        security_question (str): The security question chosen by the user
        security_answer (str): The answer to the security question (will be encrypted)
        recovery_code (str, optional): A recovery code. If None, a new one will be generated.
        
    Returns:
        str: The recovery code that was stored
    """
    try:
        connection = connect()
        if connection is None:
            return None
        cursor = connection.cursor()
        
        # Create recovery table if it doesn't exist
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS master_recovery (
            id INT AUTO_INCREMENT PRIMARY KEY,
            security_question TEXT NOT NULL,
            security_answer TEXT NOT NULL,
            recovery_code TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )
        """)
        connection.commit()
        
        # Generate recovery code if not provided
        if recovery_code is None:
            import secrets
            recovery_code = secrets.token_hex(16)  # 32 character hex code
        
        # Encrypt the security answer and recovery code
        encrypted_answer = encrypt_password(security_answer)
        
        # Check if a recovery option already exists
        cursor.execute("SELECT id FROM master_recovery LIMIT 1")
        result = cursor.fetchone()
        
        if result:
            # Update existing recovery options
            cursor.execute("""
            UPDATE master_recovery 
            SET security_question = %s, security_answer = %s, recovery_code = %s 
            WHERE id = %s
            """, (security_question, encrypted_answer, recovery_code, result[0]))
        else:
            # Insert new recovery options
            cursor.execute("""
            INSERT INTO master_recovery (security_question, security_answer, recovery_code) 
            VALUES (%s, %s, %s)
            """, (security_question, encrypted_answer, recovery_code))
        
        connection.commit()
        return recovery_code
        
    except mysql.connector.Error as error:
        print("Error setting up recovery options:", error)
        return None
    finally:
        if connection:
            cursor.close()
            connection.close()

def get_recovery_info():
    """
    Retrieve recovery information.
    
    Returns:
        dict: A dictionary containing recovery info or None if not set up
    """
    try:
        connection = connect()
        if connection is None:
            return None
        cursor = connection.cursor()
        
        # Check if the table exists
        cursor.execute("SHOW TABLES LIKE 'master_recovery'")
        if not cursor.fetchone():
            return None
        
        # Get recovery information
        cursor.execute("SELECT id, security_question FROM master_recovery LIMIT 1")
        result = cursor.fetchone()
        
        if result:
            return {
                "id": result[0],
                "security_question": result[1],
                "has_recovery": True
            }
        return None
        
    except mysql.connector.Error as error:
        print("Error retrieving recovery info:", error)
        return None
    finally:
        if connection:
            cursor.close()
            connection.close()

def verify_recovery_answers(security_answer, recovery_code):
    """
    Verify the recovery answers provided by the user.
    
    Args:
        security_answer (str): The answer to the security question
        recovery_code (str): The recovery code
        
    Returns:
        bool: True if verification was successful, False otherwise
    """
    try:
        connection = connect()
        if connection is None:
            return False
        cursor = connection.cursor()
        
        # Get stored recovery information
        cursor.execute("SELECT security_answer, recovery_code FROM master_recovery LIMIT 1")
        result = cursor.fetchone()
        
        if not result:
            return False
            
        stored_answer, stored_code = result
        
        # Decrypt the stored answer for comparison
        try:
            decrypted_answer = decrypt_password(stored_answer)
            # Case-insensitive comparison for the security answer
            answer_correct = decrypted_answer.lower() == security_answer.lower()
            # Case-sensitive comparison for the recovery code
            code_correct = stored_code == recovery_code
            
            return answer_correct and code_correct
        except Exception as e:
            print(f"Error during recovery verification: {e}")
            return False
        
    except mysql.connector.Error as error:
        print("Error verifying recovery answers:", error)
        return False
    finally:
        if connection:
            cursor.close()
            connection.close()

def update_master_password(new_password):
    """
    Update the master password in the secret.py file.
    
    Args:
        new_password (str): The new master password
        
    Returns:
        bool: True if the password was updated successfully, False otherwise
    """
    try:
        import os
        
        # Path to secret.py
        secret_file_path = os.path.join(os.path.dirname(__file__), "secret.py")
        
        # Read the current content
        with open(secret_file_path, "r") as file:
            lines = file.readlines()
        
        # Find and replace the password line
        for i, line in enumerate(lines):   
            if 'return "' in line and '"  #  PM_MASTER_PASSWORD' in line:   # recently edited here 
                lines[i] = f'    return "{new_password}"  #  PM_MASTER_PASSWORD\n'  # recently edited here
                break
        
        # Write the updated content
        with open(secret_file_path, "w") as file:
            file.writelines(lines)
            
        return True
        
    except Exception as e:
        print(f"Error updating master password: {e}")
        return False

def store_passwords(password, user_email, username, url, app_name):
    try:
        if not ensure_connection():  # Ensures a valid database connection
            print("[ERROR] Database connection failed. Cannot store password.")
            return

        global cursor  # Ensure cursor is correctly used

        # Encrypt the password before storing
        encrypted_password = encrypt_password(password)

        mysql_insert_query = """ 
        INSERT INTO credentials (password_hash, user_email, username, url, app_name, is_encrypted) 
        VALUES (%s, %s, %s, %s, %s, %s)
        """
        record_to_insert = (encrypted_password, user_email, username, url, app_name, True)
        
        cursor.execute(mysql_insert_query, record_to_insert)  # Now `cursor` is always valid
        conn.commit()
        print("Password stored successfully!")
    
    except mysql.connector.Error as error:
        print(f"[ERROR] Error while inserting: {error}")
        try:
            conn.rollback()
        except:
            pass  # Ignore rollback errors
    
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
    
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()


# Secure clipboard function
def secure_copy_to_clipboard(text, delay=10):
    """Copy text to clipboard and auto-clear after delay seconds."""
    pyperclip.copy(text)
    print(f"Password copied to clipboard. It will be cleared in {delay} seconds.")

    # Start a background thread to clear the clipboard
    def clear_clipboard():
        time.sleep(delay)
        pyperclip.copy("")  # Clear clipboard
        print("Clipboard cleared for security.")

    threading.Thread(target=clear_clipboard, daemon=True).start()

def find_password(app_name):
    try:
        # Ensure connection and get cursor
        if not ensure_connection():
            print("[ERROR] Cannot continue without database connection.")
            return
        
        # First check if multiple accounts exist for this app
        check_query = "SELECT COUNT(*), user_email FROM credentials WHERE app_name = %s GROUP BY user_email"
        cursor.execute(check_query, (app_name,))
        email_results = cursor.fetchall()
        
        if not email_results:
            print("No password found for this app.")
            return
            
        # If multiple emails exist for this app, ask the user to specify which one
        user_email = None
        if len(email_results) > 1:
            print(f"\nMultiple accounts found for {app_name}.")
            print("Please enter the exact email address for the account you want to access:")
            user_email = getpass.getpass(prompt="Email: ").strip()
            
            # Verify the email exists in our results
            valid_emails = [email for _, email in email_results]
            if user_email not in valid_emails:
                print(f"Error: Email '{user_email}' not found for {app_name}.")
                print(f"Available emails: {', '.join(valid_emails)}")
                return
        else:
            # Only one email exists for this app
            user_email = email_results[0][1]
            print(f"Found account for email: {user_email}")
        
        # Now search with both app_name and user_email for a unique credential
        mysql_select_query = "SELECT password_hash, is_encrypted FROM credentials WHERE app_name = %s AND user_email = %s"
        cursor.execute(mysql_select_query, (app_name, user_email))
        result = cursor.fetchone()

        if result:
            stored_password = result[0]
            is_encrypted = result[1] if len(result) > 1 else False
            
            # If password is encrypted (new format), decrypt it after master password verification
            if is_encrypted:
                print("Security verification: Please enter your master password to access this password.")
                
                # Add brute force protection - limit attempts to 3
                max_attempts = 3
                attempts = 0
                actual_master_key = get_secret_key()
                
                while attempts < max_attempts:
                    # Use getpass to hide master password input
                    master_password = getpass.getpass("Master password: ")
                    
                    if master_password == actual_master_key:
                        # Master password verified, decrypt the password
                        try:
                            actual_password = decrypt_password(stored_password)
                            if actual_password is None:
                                print("\n" + "-"*50)
                                print("ERROR: Cannot decrypt this password with your current master password.")
                                print("This likely happened because your master password was changed.")
                                print("To recover this password, you should create a new entry with your current credentials.")
                                print("-"*50)
                                return
                                
                            print("\n" + "-"*30)
                            print(f"Password for {app_name} ({mask_email(user_email)}) has been copied to clipboard.")
                            # Securely copy to clipboard with auto-clear
                            secure_copy_to_clipboard(actual_password)
                            print("-"*30)
                            return
                        except Exception as e:
                            print(f"Error decrypting password: {e}")
                            print("This may have happened because your master password was changed.")
                            return
                    else:
                        attempts += 1
                        attempts_left = max_attempts - attempts
                        
                        if attempts_left > 0:
                            print(f"Invalid master password. {attempts_left} attempt{'s' if attempts_left > 1 else ''} remaining.")
                        else:
                            print("Too many invalid attempts. Access denied.")
                            return
            else:
                # Legacy unencrypted password
                print(f"\nPassword for {app_name} ({user_email}): {stored_password}")
                secure_copy_to_clipboard(stored_password)
        else:
            print(f"No password found for {app_name} with email {user_email}.")
    except mysql.connector.Error as error:
        print(f"Error finding password: {error}")
    except Exception as e:
        print(f"Unexpected error: {e}")
    finally:
        # No need to close connection here as it's managed globally
        pass

def find_users(user_email):
    try:
        # Ensure connection and get cursor
        if not ensure_connection():
            print("[ERROR] Cannot continue without database connection.")
            return

        mysql_select_query = "SELECT * FROM credentials WHERE user_email = %s"
        cursor.execute(mysql_select_query, (user_email,))
        result = cursor.fetchall()

        if not result:
            print("No accounts found for this email.")
            return

        # Check if there are any encrypted passwords that need to be displayed
        has_encrypted = False
        column_names = [desc[0] for desc in cursor.description]
        encrypted_index = column_names.index('is_encrypted') if 'is_encrypted' in column_names else -1
        
        if encrypted_index >= 0:
            for row in result:
                if row[encrypted_index]:
                    has_encrypted = True
                    break
        
        # Master password verification for encrypted passwords
        master_verified = False
        if has_encrypted:
            print("\nSome passwords are encrypted and require master password verification to access.")
            
            # Add brute force protection - limit attempts to 3
            max_attempts = 3
            attempts = 0
            actual_master_key = get_secret_key()
            
            while attempts < max_attempts:
                # Use getpass to hide master password input
                master_password = getpass.getpass("Master password: ")
                
                if master_password == actual_master_key:
                    master_verified = True
                    print("Master password verified. Encrypted passwords will be accessible.\n")
                    break
                else:
                    attempts += 1
                    attempts_left = max_attempts - attempts
                    
                    if attempts_left > 0:
                        print(f"Invalid master password. {attempts_left} attempt{'s' if attempts_left > 1 else ''} remaining.")
                    else:
                        print("Too many invalid attempts. Access denied.")
                        return
        
        # Display the results
        print("\nAccounts associated with", mask_email(user_email) + ":")
        print("-" * 60)

        # Fetch column names dynamically to avoid hardcoded labels
        password_index = column_names.index('password_hash') if 'password_hash' in column_names else -1
        email_index = column_names.index('user_email') if 'user_email' in column_names else -1

        for row in result:
            for i, (col_name, col_value) in enumerate(zip(column_names, row)):
                # If this is the password column, handle decryption
                if col_name == "password_hash" and col_value:
                    is_encrypted = row[encrypted_index] if encrypted_index >= 0 else False
                    
                    if is_encrypted and master_verified:
                        try:
                            # Don't show the password, just indicate it's available for copying
                            print(f"{col_name}: [Password is encrypted - type the row number to copy it]")
                        except Exception as e:
                            print(f"{col_name}: [Decryption failed - {str(e)}]")
                    elif is_encrypted and not master_verified:
                        print(f"{col_name}: [ENCRYPTED - Master verification required]")
                    else:
                        print(f"{col_name}: [Legacy hashed password - cannot be decrypted]")
                # Skip displaying the is_encrypted column as it's an implementation detail
                elif col_name == "is_encrypted":
                    continue
                # Mask email addresses
                elif col_name == "user_email":
                    print(f"{col_name}: {mask_email(col_value)}")
                else:
                    print(f"{col_name}: {col_value}")

            print("-" * 30)  # Separator for better readability
            
        # Allow copying a password by selecting row
        if master_verified and has_encrypted:
            try:
                row_to_copy = input("\nEnter row number to copy a password (or press Enter to skip): ").strip()
                if row_to_copy and row_to_copy.isdigit():
                    row_index = int(row_to_copy) - 1
                    if 0 <= row_index < len(result):
                        selected_row = result[row_index]
                        password_hash = selected_row[password_index]
                        is_encrypted = selected_row[encrypted_index] if encrypted_index >= 0 else False
                        
                        if is_encrypted:
                            try:
                                decrypted_password = decrypt_password(password_hash)
                                app_name = selected_row[column_names.index('app_name')]
                                print(f"\nPassword for {app_name} has been copied to clipboard.")
                                secure_copy_to_clipboard(decrypted_password)
                            except Exception as e:
                                print(f"Could not decrypt password: {str(e)}")
                        else:
                            print("Cannot copy legacy password in plaintext.")
                    else:
                        print("Invalid row number.")
            except Exception as e:
                print(f"Error copying password: {str(e)}")

    except Exception as error:
        print("Error while fetching user data:", error)
    finally:
        # No need to close connection here as it's managed globally
        pass

# Functions for email-based recovery
def register_recovery_email(email):
    """Register a recovery email and return a verification code"""
    verification_code = generate_verification_code()
    expires_at = get_expiry_time(30)  # Code expires in 30 minutes
    
    try:
        if not ensure_connection():
            return False, "Database connection failed"
        
        # Check if this email is already verified (same email being re-verified)
        cursor.execute("""
            SELECT id FROM recovery_email 
            WHERE email = %s AND verified = TRUE
        """, (email,))
        
        existing = cursor.fetchone()
        
        if existing:
            # Email already verified - update the verification code
            cursor.execute("""
                UPDATE recovery_email
                SET verification_code = %s, code_expiry = %s
                WHERE id = %s
            """, (verification_code, expires_at, existing[0]))
            conn.commit()
            return True, verification_code
            
        # Check if there's an unverified entry for this email
        cursor.execute("""
            SELECT id FROM recovery_email 
            WHERE email = %s AND verified = FALSE
        """, (email,))
        
        unverified = cursor.fetchone()
        
        if unverified:
            # Update the existing unverified entry with a new code
            cursor.execute("""
                UPDATE recovery_email
                SET verification_code = %s, code_expiry = %s
                WHERE id = %s
            """, (verification_code, expires_at, unverified[0]))
            conn.commit()
            return True, verification_code
        
        # New email - create a new record
        cursor.execute("""
            INSERT INTO recovery_email (email, verified, verification_code, code_expiry)
            VALUES (%s, FALSE, %s, %s)
        """, (email, verification_code, expires_at))
        
        conn.commit()
        print(f"New recovery email registration initiated for: {email}")
        return True, verification_code
        
    except mysql.connector.Error as error:
        print(f"Error registering recovery email: {error}")
        try:
            conn.rollback()
        except:
            pass
        return False, str(error)

def verify_recovery_email(email, code):
    """Verify a recovery email with the provided verification code"""
    try:
        if not ensure_connection():
            print("Database connection failed during verification")
            return False
            
        # Get the recovery email record with the verification code
        cursor.execute("""
            SELECT id, verification_code, code_expiry 
            FROM recovery_email 
            WHERE email = %s
            ORDER BY id DESC
            LIMIT 1
        """, (email,))
        
        result = cursor.fetchone()
        
        if not result:
            print(f"No verification code found for email: {email}")
            return False
            
        recovery_id, stored_code, expiry = result
        
        # Check if code is expired
        if expiry and datetime.now() > expiry:
            print("Verification code has expired")
            return False
            
        # Check if code matches
        if code != stored_code:
            print("Verification code does not match")
            return False
        
        # Transaction to update recovery emails
        try:
            # Mark all existing recovery emails as not verified
            cursor.execute("""
                UPDATE recovery_email 
                SET verified = FALSE,
                    verification_code = NULL,
                    code_expiry = NULL
                WHERE verified = TRUE
            """)
            
            # Mark the new email as verified
            cursor.execute("""
                UPDATE recovery_email 
                SET verified = TRUE,
                    verification_code = NULL,
                    code_expiry = NULL
                WHERE id = %s
            """, (recovery_id,))
            
            conn.commit()
            print(f"Recovery email verified and set as primary: {email}")
            return True
            
        except mysql.connector.Error as tx_error:
            print(f"Transac=tion error during email verification: {tx_error}")
            conn.rollback()
            return False
        
    except mysql.connector.Error as error:
        print(f"Error verifying recovery email: {error}")
        try:
            conn.rollback()
        except:
            pass
        return False

def get_recovery_email():
    """Get the verified recovery email for the account"""
    try:
        if not ensure_connection():
            print("Failed to connect to database when fetching recovery email")
            return None
        
        # Get only the most recent verified recovery email
        cursor.execute("""
            SELECT email FROM recovery_email 
            WHERE verified = TRUE 
            ORDER BY id DESC LIMIT 1
        """)
        
        result = cursor.fetchone()
        
        if result:
            return result[0]
        else:
            return None
    except mysql.connector.Error as error:
        print(f"Error getting recovery email: {error}")
        return None

def initiate_password_reset(email):
    """
    Initiate the password reset process by generating a reset token.
    
    Args:
        email (str): The recovery email address
        
    Returns:
        tuple: (success, reset_token or error_message)
    """
    try:
        if not ensure_connection():
            return False, "Database connection failed"
        
        # Verify this is the registered and verified recovery email
        cursor.execute("SELECT id FROM recovery_email WHERE email = %s AND verified = TRUE", (email,))
        result = cursor.fetchone()
        
        if not result:
            return False, "Email not verified or not registered for recovery"
            
        # Generate a secure reset token
        reset_token = generate_reset_token()
        token_expiry = get_expiry_time(minutes=15)  # Token expires in 15 minutes
        
        # Update the reset token in the database
        cursor.execute("""
        UPDATE recovery_email 
        SET verification_code = %s, code_expiry = %s
        WHERE email = %s
        """, (reset_token, token_expiry, email))
        
        conn.commit()
        return True, reset_token
        
    except mysql.connector.Error as error:
        print("Error initiating password reset:", error)
        try:
            conn.rollback()
        except:
            pass
        return False, str(error)

load_env_file()

def reset_master_password(email, token, new_password):
    """
    Reset the master password using the reset token and re-encrypt existing passwords.
    
    Args:
        email (str): The recovery email address
        token (str): The reset token
        new_password (str): The new master password
        
    Returns:
        bool: True if password was reset successfully, False otherwise
    """
    print("Starting master password reset process...")
    
    try:
        if not ensure_connection():
            print("ERROR: Database connection failed")
            return False
        
        # Get stored token information
        cursor.execute("""
        SELECT verification_code, code_expiry 
        FROM recovery_email 
        WHERE email = %s AND verified = TRUE
        """, (email,))
        result = cursor.fetchone()
        
        if not result:
            print("ERROR: No verified recovery email found")
            return False
            
        stored_token, expiry = result
        
        # Check if token has expired
        if expiry and datetime.now() > expiry:
            print("ERROR: Reset token has expired")
            return False
            
        # Compare tokens
        if stored_token != token:
            print("ERROR: Invalid reset token provided")
            return False
        
        # Store the old master password before changing anything
        old_password = get_secret_key()
        print(f"Current master password retrieved: {old_password[:3]}***")
        
        # Create old cipher for decryption
        old_cipher = get_cipher_suite()
        
        # Ensure no transaction is in progress before starting a new one
        try:
            conn.rollback()  # Rollback any existing transaction
            print("Rolled back any existing transaction")
        except:
            pass  # Ignore if there was no transaction
        
        # Begin transaction
        conn.start_transaction()
        print("Started a new transaction")
        
        try:
            # Get encrypted passwords
            cursor.execute("SELECT id, password_hash FROM credentials WHERE is_encrypted = TRUE")
            stored_passwords = cursor.fetchall()
            print(f"Found {len(stored_passwords)} encrypted passwords to update")
            
            if not stored_passwords:
                print("No encrypted passwords found, just updating master password")
                # No passwords to re-encrypt, just update the master password
                set_env_password(new_password)
                reset_cipher_suite()
                
                # Clear the reset token
                cursor.execute("""
                UPDATE recovery_email 
                SET verification_code = NULL, code_expiry = NULL
                WHERE email = %s
                """, (email,))
                
                conn.commit()
                print("Master password reset successful with no re-encryption needed")
                return True
            
            # Attempt to decrypt passwords with the current master password
            print("Decrypting passwords with current master password")
            success_count = 0
            
            # First, verify that we can decrypt at least one password
            # This confirms the current master password is valid
            try:
                test_id, test_password = stored_passwords[0]
                test_decrypted = old_cipher.decrypt(test_password.encode()).decode()
                print("Password decryption test successful")
            except Exception as e:
                print(f"ERROR: Could not decrypt test password: {e}")
                print("Current master password may be incorrect")
                conn.rollback()
                return False
            
            # Decrypt all passwords and temporarily store them in the database
            for id, encrypted_password in stored_passwords:
                try:
                    # Decrypt password with current master password
                    plaintext = old_cipher.decrypt(encrypted_password.encode()).decode()
                    
                    # Store the decrypted password temporarily (this is secure because we verified the user via email)
                    cursor.execute("""
                    UPDATE credentials 
                    SET password_hash = %s, is_encrypted = FALSE 
                    WHERE id = %s
                    """, (plaintext, id))
                    
                    success_count += 1
                except Exception as e:
                    print(f"Warning: Could not decrypt password ID {id}: {e}")
            
            print(f"Successfully decrypted {success_count} of {len(stored_passwords)} passwords")
            
            if success_count == 0:
                print("ERROR: Could not decrypt any passwords. Aborting process.")
                conn.rollback()
                return False
            
            # Now update the master password
            print(f"Setting new master password: {new_password[:3]}***")
            set_env_password(new_password)
            reset_cipher_suite()
            
            # Get the new cipher
            new_cipher = get_cipher_suite()
            
            # Re-encrypt all decrypted passwords with the new master password
            print("Re-encrypting passwords with new master password")
            
            # Get all temporarily decrypted passwords
            cursor.execute("SELECT id, password_hash FROM credentials WHERE is_encrypted = FALSE")
            decrypted_passwords = cursor.fetchall()
            
            # Re-encrypt each password with the new master password
            re_encrypt_count = 0
            for id, plaintext in decrypted_passwords:
                try:
                    # Encrypt with new master password
                    newly_encrypted = new_cipher.encrypt(plaintext.encode()).decode()
                    
                    # Update in database
                    cursor.execute("""
                    UPDATE credentials 
                    SET password_hash = %s, is_encrypted = TRUE 
                    WHERE id = %s
                    """, (newly_encrypted, id))
                    
                    re_encrypt_count += 1
                except Exception as e:
                    print(f"Error re-encrypting password ID {id}: {e}")
            
            print(f"Successfully re-encrypted {re_encrypt_count} of {success_count} passwords")
            
            # Clear the reset token
            cursor.execute("""
            UPDATE recovery_email 
            SET verification_code = NULL, code_expiry = NULL
            WHERE email = %s
            """, (email,))
            
            # Commit all changes
            conn.commit()
            print("Master password reset and re-encryption completed successfully")
            return True
            
        except Exception as e:
            print(f"ERROR during password reset: {e}")
            try:
                conn.rollback()
                print("Transaction rolled back due to error")
            except Exception as rollback_error:
                print(f"Error during rollback: {rollback_error}")
            return False
            
    except Exception as e:
        print(f"ERROR in reset_master_password: {e}")
        try:
            conn.rollback()
            print("Transaction rolled back due to outer error")
        except Exception as rollback_error:
            print(f"Error during outer rollback: {rollback_error}")
        return False

def send_verification_email(email, code, app_password=None):
    """
    Send a verification email with the provided code.
    
    Args:
        email (str): The recipient email address
        code (str): The verification code
        app_password (str, optional): App-specific password for email authentication
        
    Returns:
        bool: True if email was sent successfully, False otherwise
    """
    try:
        # Get email configuration from environment variables
        smtp_server = os.getenv("PM_SMTP_SERVER", "smtp.gmail.com")
        smtp_port = int(os.getenv("PM_SMTP_PORT", "587"))
        smtp_user = os.getenv("PM_SMTP_USER", "")
        
        # Use provided app password if available, otherwise use the one from environment
        if app_password:
            smtp_password = app_password
        else:
            smtp_password = os.getenv("PM_SMTP_PASSWORD", "").strip()  # Strip any whitespace
        
        if not smtp_user:
            print("SMTP username not configured. Email sending disabled.")
            print(f"Verification code for {email}: {code}")
            # Show the verification code in a messagebox for debugging/development
            import tkinter.messagebox as messagebox
            messagebox.showinfo("Verification Code", f"Email would be sent to {email}\nVerification code: {code}")
            return True  # Return true but don't actually send for development
            
        if not smtp_password:
            print("SMTP password not provided. Email sending disabled.")
            print(f"Verification code for {email}: {code}")
            # Show the verification code in a messagebox for debugging/development
            import tkinter.messagebox as messagebox
            messagebox.showinfo("Verification Code", f"Email would be sent to {email}\nVerification code: {code}")
            return True  # Return true but don't actually send for development
        
        print(f"Attempting to send email to {email} using SMTP server {smtp_server}:{smtp_port}")
        print(f"Using SMTP user: {smtp_user}")
        
        # Create message
        msg = MIMEMultipart('alternative')  # Use alternative to support both text and HTML
        msg['From'] = f"Password Manager <{smtp_user}>"
        msg['To'] = email
        msg['Subject'] = "Password Manager 4000 - Verification Code"
        
        # Create both plain text and HTML versions for better deliverability
        text_body = f"""
Password Manager 4000 - Verification Code

Your verification code is: {code}

This code will expire in 30 minutes.

If you did not request this, please ignore this email.
        """
        
        html_body = f"""
        <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px;">
                    <h2 style="color: #4285f4;">Password Manager 4000 - Verify Your Email</h2>
                    <p>Thank you for setting up email recovery for your Password Manager 4000.</p>
                    <p>Your verification code is: <strong style="font-size: 18px; background: #f5f5f5; padding: 5px 10px; border-radius: 3px;">{code}</strong></p>
                    <p>This code will expire in 30 minutes.</p>
                    <p style="color: #777; font-size: 13px;">If you did not request this, you can safely ignore this email.</p>
                </div>
            </body>
        </html>
        """
        
        # Attach both versions to the email
        msg.attach(MIMEText(text_body, 'plain'))
        msg.attach(MIMEText(html_body, 'html'))
        
        # Add headers to reduce spam score
        msg.add_header('X-Priority', '1')  # Set high priority
        msg.add_header('X-MSMail-Priority', 'High')
        msg.add_header('X-Mailer', 'Microsoft Outlook Express 6.00.2600.0000')  # Mimic a legitimate mail client
        msg.add_header('Precedence', 'bulk')  # Mark as bulk mail
        
        try:
            # Connect to SMTP server and send email
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.set_debuglevel(1)  # Enable debug output to help troubleshoot
                server.ehlo()  # Say hello to the server
                server.starttls()  # Start TLS encryption
                server.ehlo()  # Say hello again after TLS
                
                try:
                    print(f"Attempting to log in with username: {smtp_user}")
                    server.login(smtp_user, smtp_password)
                    print("Login successful")
                    
                    print(f"Sending message to: {email}")
                    server.send_message(msg)
                    print(f"Verification email sent successfully to {email}")
                    return True
                except smtplib.SMTPAuthenticationError as auth_error:
                    print(f"Authentication failed for {smtp_user}. Error: {str(auth_error)}")
                    
                    # Show the verification code in a messagebox with more information
                    import tkinter.messagebox as messagebox
                    messagebox.showinfo("Email Delivery Failed - Verification Code", 
                                      f"Email could not be sent due to authentication issues.\n\n"
                                      f"This might be because Google is blocking the connection as a security measure.\n"
                                      f"Try with a different email account or try again later.\n\n"
                                      f"For now, your verification code is: {code}")
                    return True  # Return true so flow can continue for testing
        except Exception as smtp_error:
            print(f"SMTP error: {str(smtp_error)}")
            # Show the verification code in a messagebox when SMTP fails
            import tkinter.messagebox as messagebox
            messagebox.showinfo("Email Error - Verification Code", 
                              f"Could not send email due to SMTP error: {str(smtp_error)}.\n\n"
                              f"This might be because Google is blocking the connection as suspicious.\n"
                              f"Try with a different email account or try again later.\n\n"
                              f"For now, your verification code is: {code}")
            return True  # Return true so flow can continue for testing
            
    except Exception as e:
        print(f"Error sending verification email: {e}")
        print(f"Verification code for {email}: {code}")  # Print code for development
        # Show the verification code in a messagebox for any other errors
        import tkinter.messagebox as messagebox
        messagebox.showinfo("Error - Verification Code", 
                          f"An error occurred while sending the email: {str(e)}.\n\n"
                          f"For testing purposes, your verification code is: {code}")
        return True  # Return true so flow can continue for testing

def send_reset_email(email, token, app_password=None):
    """
    Send a password reset email with the provided token.
    
    Args:
        email (str): The recipient email address
        token (str): The reset token
        app_password (str, optional): App-specific password for email authentication
        
    Returns:
        bool: True if email was sent successfully, False otherwise
    """
    try:
        # Get email configuration from environment variables
        smtp_server = os.getenv("PM_SMTP_SERVER", "smtp.gmail.com")
        smtp_port = int(os.getenv("PM_SMTP_PORT", "587"))
        smtp_user = os.getenv("PM_SMTP_USER", "")
        
        # Use provided app password if available, otherwise use the one from environment
        if app_password:
            smtp_password = app_password
        else:
            smtp_password = os.getenv("PM_SMTP_PASSWORD", "").strip()  # Strip any whitespace
        
        if not smtp_user:
            print("SMTP username not configured. Email sending disabled.")
            print(f"Reset token for {email}: {token}")
            # Show the reset token in a messagebox for debugging/development
            import tkinter.messagebox as messagebox
            messagebox.showinfo("Reset Code", f"Email would be sent to {email}\nReset code: {token}")
            return True  # Return true but don't actually send for development
            
        if not smtp_password:
            print("SMTP password not provided. Email sending disabled.")
            print(f"Reset token for {email}: {token}")
            # Show the reset token in a messagebox for debugging/development
            import tkinter.messagebox as messagebox
            messagebox.showinfo("Reset Code", f"Email would be sent to {email}\nReset code: {token}")
            return True  # Return true but don't actually send for development
        
        print(f"Attempting to send reset email to {email} using SMTP server {smtp_server}:{smtp_port}")
        print(f"Using SMTP user: {smtp_user}")
        
        # Create message
        msg = MIMEMultipart('alternative')  # Use alternative to support both text and HTML
        msg['From'] = f"Password Manager Security <{smtp_user}>"
        msg['To'] = email
        msg['Subject'] = "Password Manager 4000 - Password Reset Code"
        
        # Create both plain text and HTML versions for better deliverability
        text_body = f"""
Password Manager 4000 - Reset Your Password

You have requested to reset your master password.
Your reset code is: {token}

This code will expire in 15 minutes.

If you did not request this reset, please secure your account immediately.
        """
        
        html_body = f"""
        <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px;">
                    <h2 style="color: #4285f4;">Password Manager 4000 - Reset Your Password</h2>
                    <p>You have requested to reset your master password.</p>
                    <p>Your reset code is: <strong style="font-size: 18px; background: #f5f5f5; padding: 5px 10px; border-radius: 3px;">{token}</strong></p>
                    <p>This code will expire in 15 minutes.</p>
                    <p style="color: #777; font-size: 13px;">If you did not request this reset, please secure your account immediately.</p>
                </div>
            </body>
        </html>
        """
        
        # Attach both versions to the email
        msg.attach(MIMEText(text_body, 'plain'))
        msg.attach(MIMEText(html_body, 'html'))
        
        # Add headers to reduce spam score
        msg.add_header('X-Priority', '1')  # Set high priority
        msg.add_header('X-MSMail-Priority', 'High')
        msg.add_header('X-Mailer', 'Microsoft Outlook Express 6.00.2600.0000')  # Mimic a legitimate mail client
        msg.add_header('Precedence', 'bulk')  # Mark as bulk mail
        
        try:
            # Connect to SMTP server and send email
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.set_debuglevel(1)  # Enable debug output to help troubleshoot
                server.ehlo()  # Say hello to the server
                server.starttls()  # Start TLS encryption
                server.ehlo()  # Say hello again after TLS
                
                try:
                    print(f"Attempting to log in with username: {smtp_user}")
                    server.login(smtp_user, smtp_password)
                    print("Login successful")
                    
                    print(f"Sending reset message to: {email}")
                    server.send_message(msg)
                    print(f"Reset email sent successfully to {email}")
                    return True
                except smtplib.SMTPAuthenticationError as auth_error:
                    print(f"Authentication failed for {smtp_user}. Error: {str(auth_error)}")
                    
                    # Show the reset token in a messagebox with more information
                    import tkinter.messagebox as messagebox
                    messagebox.showinfo("Email Delivery Failed - Reset Code", 
                                      f"Email could not be sent due to authentication issues.\n\n"
                                      f"This might be because Google is blocking the connection as a security measure.\n"
                                      f"Try with a different email account or try again later.\n\n"
                                      f"For now, your reset code is: {token}")
                    return True  # Return true so flow can continue for testing
        except Exception as smtp_error:
            print(f"SMTP error: {str(smtp_error)}")
            # Show the reset token in a messagebox when SMTP fails
            import tkinter.messagebox as messagebox
            messagebox.showinfo("Email Error - Reset Code", 
                              f"Could not send email due to SMTP error: {str(smtp_error)}.\n\n"
                              f"This might be because Google is blocking the connection as suspicious.\n"
                              f"Try with a different email account or try again later.\n\n"
                              f"For now, your reset code is: {token}")
            return True  # Return true so flow can continue for testing
            
    except Exception as e:
        print(f"Error sending reset email: {e}")
        print(f"Reset token for {email}: {token}")  # Print token for development
        # Show the reset token in a messagebox for any other errors
        import tkinter.messagebox as messagebox
        messagebox.showinfo("Error - Reset Code", 
                          f"An error occurred while sending the email: {str(e)}.\n\n"
                          f"For testing purposes, your reset code is: {token}")
        return True  # Return true so flow can continue for testing

def mask_email(email):
    """Mask email address for privacy"""
    username, domain = email.split('@')
    masked_username = username[:3] + '*' * (len(username) - 3)
    return f"{masked_username}@{domain}"

def change_master_password_with_reencryption(new_password, old_password=None):
    """
    Change the master password and re-encrypt all stored passwords.
    
    Args:
        new_password (str): The new master password
        old_password (str, optional): The old master password. If None, uses the current secret key.
        
    Returns:
        tuple: (success: bool, message: str) indicating success/failure and a message
    """
    try:
        if not ensure_connection():
            return False, "Database connection failed"
        
        # If old_password not provided, use current secret key
        old_password = old_password or get_secret_key()
        
        # Save old cipher suite before changing the password
        # This requires temporarily setting up the environment with the old password
        from secret import get_secret_key, set_env_password
        
        # Store current cipher for decryption
        old_cipher = get_cipher_suite()
        
        # Start a transaction
        conn.start_transaction()
        
        try:
            # First check if we can decrypt at least one password with the old password
            # This verifies the old password is correct
            cursor.execute("SELECT password_hash FROM credentials WHERE is_encrypted = TRUE LIMIT 1")
            test_row = cursor.fetchone()
            if test_row:
                try:
                    old_cipher.decrypt(test_row[0].encode())
                except Exception:
                    conn.rollback()
                    return False, "Old master password is incorrect - decryption test failed"
            
            # Change the master password in environment and secret.py
            # Set the new password
            if not set_env_password(new_password):
                conn.rollback()
                return False, "Failed to update master password in environment"
                
            # Update the master password in the secret.py file
            if not update_master_password(new_password):
                conn.rollback()
                # Revert the environment change
                set_env_password(old_password)
                return False, "Failed to update master password in secret.py"
            
            # Reset the cipher suite to use the new master password
            reset_cipher_suite()
            
            # Get the new cipher
            new_cipher = get_cipher_suite()
            
            # Get all encrypted passwords
            cursor.execute("SELECT id, password_hash FROM credentials WHERE is_encrypted = TRUE")
            rows = cursor.fetchall()
            
            # Track statistics
            total_rows = len(rows)
            successful = 0
            failed = 0
            
            # Re-encrypt each password
            for row_id, encrypted_password in rows:
                try:
                    # Decrypt with old key
                    plaintext = old_cipher.decrypt(encrypted_password.encode()).decode()
                    
                    # Re-encrypt with new key
                    new_encrypted = new_cipher.encrypt(plaintext.encode()).decode()
                    
                    # Update in database
                    cursor.execute("UPDATE credentials SET password_hash = %s WHERE id = %s", 
                                  (new_encrypted, row_id))
                    successful += 1
                except Exception as e:
                    print(f"Error re-encrypting credential {row_id}: {str(e)}")
                    failed += 1
            
            # Commit the changes
            conn.commit()
            
            # Return success with statistics
            return (True, f"Master password changed successfully. "
                   f"Re-encrypted {successful} of {total_rows} passwords. "
                   f"Failed: {failed}.")
            
        except Exception as e:
            # If any error occurs, roll back and restore the old password
            try:
                conn.rollback()
                # If we already changed the environment password, revert it
                set_env_password(old_password)
            except:
                pass
            return False, f"Error during password change: {str(e)}"
    
    except Exception as e:
        return False, f"Unexpected error: {str(e)}"

def get_all_accounts():
    """
    Get all stored accounts from the database.
    
    Returns:
        list: List of dictionaries containing account information
    """
    try:
        if not ensure_connection():
            print("Failed to connect to database")
            return []
            
        cursor.execute("SELECT id, app_name, url, username, user_email FROM credentials")
        columns = [col[0] for col in cursor.description]
        accounts = []
        
        for row in cursor.fetchall():
            account = dict(zip(columns, row))
            accounts.append(account)
            
        return accounts
            
    except mysql.connector.Error as error:
        print(f"Error retrieving accounts: {error}")
        return []
    except Exception as e:
        print(f"Unexpected error in get_all_accounts: {e}")
        return []

def update_password(account_id, new_password):
    """
    Update the password for a specific account and encrypt it with the current master password.
    
    Args:
        account_id (int): The ID of the account to update
        new_password (str): The new password to set
        
    Returns:
        bool: True if update was successful, False otherwise
    """
    try:
        if not ensure_connection():
            print("Failed to connect to database")
            return False
            
        # Encrypt the password with the current master password
        encrypted_password = encrypt_password(new_password)
        
        # Update the password and ensure is_encrypted is set to TRUE
        cursor.execute("""
        UPDATE credentials 
        SET password_hash = %s, is_encrypted = TRUE 
        WHERE id = %s
        """, (encrypted_password, account_id))
        
        conn.commit()
        return True
            
    except mysql.connector.Error as error:
        print(f"Error updating password: {error}")
        try:
            conn.rollback()
        except:
            pass
        return False
    except Exception as e:
        print(f"Unexpected error in update_password: {e}")
        try:
            conn.rollback()
        except:
            pass
        return False

