import tkinter as tk
from tkinter import messagebox, ttk, simpledialog
import mysql.connector
from PIL import Image, ImageTk
import os
from secret import get_secret_key
from hash_maker import password as generate_password
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import threading
import time
from database_manager import setup_recovery_options, get_recovery_info, verify_recovery_answers, update_master_password
from database_manager import get_recovery_email, register_recovery_email, verify_recovery_email, send_verification_email
from database_manager import initiate_password_reset, reset_master_password, send_reset_email
from secret import load_env_file
import re
import sys
import pyperclip
import datetime
import secrets
import string
import webbrowser

load_env_file()  # Load environment variables from .env file

# Initialize encryption functionality
def get_encryption_key():
    # Use the secret key to derive an encryption key
    secret = get_secret_key()
    # We need a 32-byte key for Fernet
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
cipher_suite = None  # Initialize as None, will be created when needed

def get_cipher_suite():
    """Get a fresh cipher suite using the current master password"""
    global cipher_suite
    if cipher_suite is None:
       cipher_suite = Fernet(get_encryption_key())
    return cipher_suite

def encrypt_password(password):
    cipher = get_cipher_suite()
    return cipher.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    cipher = get_cipher_suite()
    return cipher.decrypt(encrypted_password.encode()).decode()

SECRET_KEY = get_secret_key()

# Database Connection
conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="2004",
    database="password_manager",
    autocommit=False,  # Explicit transaction control
    connection_timeout=30,
    use_pure=True  # Use pure Python implementation
)
cursor = conn.cursor(buffered=True)  # Use buffered cursor

# Function to check and reconnect database if needed
def ensure_connection():
    global conn, cursor
    try:
        if not conn.is_connected():
            print("Database connection lost. Reconnecting...")
            conn.reconnect(attempts=3, delay=0.5)
            cursor = conn.cursor(buffered=True)
            print("Reconnected to database")
        return True
    except mysql.connector.Error as error:
        print(f"Database connection error: {error}")
        return False

# Ensure the database schema has the is_encrypted column
def ensure_schema():
    try:
        ensure_connection()
        cursor.execute("SHOW COLUMNS FROM credentials LIKE 'is_encrypted'")
        result = cursor.fetchone()
        
        # If the column doesn't exist, add it
        if not result:
            cursor.execute("ALTER TABLE credentials ADD COLUMN is_encrypted BOOLEAN DEFAULT FALSE")
            conn.commit()
            print("Schema updated with encryption tracking.")
    except mysql.connector.Error as error:
        print("Error updating schema:", error)

# Call ensure_schema to make sure our database is ready
ensure_schema()

# Initialize Tkinter
root = tk.Tk()

# Load images
image_path = os.path.join(os.path.dirname(__file__), "logo.jpg")
logo_img = Image.open(image_path)
logo_img = logo_img.resize((100, 100), Image.LANCZOS)
logo_photo = ImageTk.PhotoImage(logo_img)

# Global variables
clipboard_threads = []
current_password_to_copy = ""
failed_master_password_attempts = 0
max_password_attempts = 3
account_locked = False
attempts_allowed = 3
current_attempts = 0
authentication_successful = False
is_verified = False
reset_token_value = None
recovery_password_frame = None

# Create frames but don't pack them yet - these will be used in create_main_app
home_frame = None
search_frame = None
manage_frame = None
search_email_entry = None
search_entry = None
search_result_label = None
copy_button = None
entry_app_name = None
entry_url = None
entry_username = None
entry_user_email = None
entry_password = None
tree = None

def create_main_menu():
    """Create the main menu bar"""
    menubar = tk.Menu(root)
    root.config(menu=menubar)
    
    # File menu
    file_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="File", menu=file_menu)
    file_menu.add_command(label="Exit", command=root.quit)
    
    # Security menu
    security_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Security", menu=security_menu)
    security_menu.add_command(label="Setup Password Recovery", command=setup_recovery_gui)
    security_menu.add_command(label="Configure Email Settings", command=lambda: __import__('configure_email').configure_email_settings())
    
    # Help menu
    help_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Help", menu=help_menu)
    help_menu.add_command(label="About", command=lambda: messagebox.showinfo("About", "Password Manager 4000\nVersion 1.0\nA secure password management solution"))

def create_main_app():
    """Create the main application interface after successful login"""
    global home_frame, search_frame, manage_frame, search_email_entry, search_entry
    global search_result_label, copy_button, entry_app_name, entry_url
    global entry_username, entry_user_email, entry_password, tree
    
    root.title("Password Manager 4000")
    root.geometry("900x550")  # Standardized window size
    root.configure(bg="#f0f0f0")
    
    # Create menu bar
    create_main_menu()
    
    # Create frames
    home_frame = tk.Frame(root, bg="#f0f0f0")
    search_frame = tk.Frame(root, bg="#f0f0f0")
    manage_frame = tk.Frame(root, bg="#f0f0f0")
    
    # Home Page
    logo_label = tk.Label(home_frame, image=logo_photo, bg="#f0f0f0")
    logo_label.pack()
    
    tk.Label(home_frame, text="Welcome to Password Manager 4000", font=("Arial", 16), bg="#f0f0f0").pack()
    
    tk.Button(home_frame, text="Manage Credentials", command=open_manage_page, bg="#4CAF50", fg="white").pack(pady=10)
    tk.Button(home_frame, text="Search Credential", command=open_search_page, bg="#008CBA", fg="white").pack(pady=10)
    tk.Button(home_frame, text="Exit", command=root.quit, bg="#f44336", fg="white").pack(pady=10)
    
    # Search Page
    tk.Label(search_frame, text="Search Credential", font=("Arial", 14), bg="#f0f0f0").pack()
    
    tk.Label(search_frame, text="Enter Your Email:", bg="#f0f0f0").pack()
    search_email_entry = tk.Entry(search_frame)
    search_email_entry.pack(pady=5)
    
    tk.Label(search_frame, text="Enter App Name:", bg="#f0f0f0").pack()
    search_entry = tk.Entry(search_frame)
    search_entry.pack(pady=5)
    
    tk.Button(search_frame, text="Search", command=search_credential, bg="#008CBA", fg="white").pack(pady=5)
    
    search_result_label = tk.Label(search_frame, text="", font=("Arial", 12), bg="#f0f0f0")
    search_result_label.pack(pady=5)
    
    copy_button = tk.Button(search_frame, text="Copy Password", bg="#4CAF50", fg="white")
    
    tk.Button(search_frame, text="Back to Home", command=go_home, bg="#f44336", fg="white").pack(pady=5)
    
    # Manage Credentials Page
    tk.Button(manage_frame, text="Back to Home", command=go_home, bg="#f44336", fg="white").pack(pady=5)
    
    frame = tk.Frame(manage_frame, bg="#f0f0f0")
    frame.pack(pady=20)
    
    labels = ["App Name:", "URL:", "Username:", "Email:", "Password:"]
    entries = []
    
    for i, text in enumerate(labels):
        tk.Label(frame, text=text, bg="#f0f0f0").grid(row=i, column=0, padx=10, pady=5)
        entry = tk.Entry(frame)
        entry.grid(row=i, column=1, padx=10, pady=5)
        entries.append(entry)
    
    entry_app_name, entry_url, entry_username, entry_user_email, entry_password = entries
    
    # Add Generate Password button
    generate_btn = tk.Button(frame, text="Generate Password", command=generate_secure_password, bg="#FF9800", fg="white")
    generate_btn.grid(row=4, column=2, padx=10, pady=5)
    
    button_frame = tk.Frame(manage_frame, bg="#f0f0f0")
    button_frame.pack(pady=10)
    
    tk.Button(button_frame, text="Add", command=add_credential, 
            bg="#4CAF50", fg="white").grid(row=0, column=0, padx=5)
    tk.Button(button_frame, text="Edit", command=edit_credential, 
            bg="#FF9800", fg="white").grid(row=0, column=1, padx=5)
    tk.Button(button_frame, text="Delete", command=delete_credential, 
            bg="#f44336", fg="white").grid(row=0, column=2, padx=5)
    tk.Button(button_frame, text="Access Password", command=view_password, 
            bg="#9C27B0", fg="white").grid(row=0, column=3, padx=5)
    tk.Button(button_frame, text="Refresh", command=display_credentials, 
            bg="#008CBA", fg="white").grid(row=0, column=4, padx=5)
    tk.Button(button_frame, text="url", command=display_url, 
            bg="#4CAF50", fg="white").grid(row=0, column=5, padx=5)
    
    # Treeview widget
    tree = ttk.Treeview(manage_frame, columns=("ID", "App Name", "URL", "Username", "Email"), show="headings")
    tree.heading("ID", text="ID")
    tree.heading("App Name", text="App Name")
    tree.heading("URL", text="URL")
    tree.heading("Username", text="Username")
    tree.heading("Email", text="Email")
    tree.pack(pady=10, fill="both", expand=True)
    
    # Show the home frame initially
    home_frame.pack(pady=20)

# Validation functions
def is_valid_email(email):
    """Validate email format"""
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return bool(re.match(pattern, email))

def is_valid_url(url):
    """Validate URL format"""
    pattern = r'^(https?:\/\/)?(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)$'
    return bool(re.match(pattern, url))

# Function to validate inputs
def validate_credential_inputs(app_name, url, user_email, password):
    """Validate all credential inputs and return dictionary of errors"""
    errors = []
    
    if not app_name:
        errors.append("App name is required")
    
    if not url:
        errors.append("URL is required")
    elif not is_valid_url(url):
        errors.append("URL is not valid")
    
    if not user_email:
        errors.append("Email is required")
    elif not is_valid_email(user_email):
        errors.append("Email format is not valid")
    
    if not password:
        errors.append("Password is required")
    
    return errors

# Function to reset the cipher suite
def reset_cipher_suite():
    """Reset the cipher suite to force recreation with current master password"""
    global cipher_suite
    cipher_suite = None

# Function to verify master password
def verify_master_password():
    global failed_master_password_attempts, account_locked
    
    # Check if account is locked due to too many failed attempts
    if account_locked:
        messagebox.showerror("Account Locked", "Too many failed attempts. Application is locked for security.")
        return False
    
    password = simpledialog.askstring("Security Verification", "Enter master password:", show="*")
    
    # User cancelled the dialog
    if password is None:
        return False
        
    if password == SECRET_KEY:
        # Reset failed attempts counter on successful login
        failed_master_password_attempts = 0
        # Reset cipher suite to ensure it uses the correct master password
        reset_cipher_suite()
        return True
    else:
        # Increment failed attempts counter
        failed_master_password_attempts += 1
        
        # Calculate attempts remaining
        attempts_left = max_password_attempts - failed_master_password_attempts
        
        if attempts_left <= 0:
            # Lock the account if max attempts reached
            account_locked = True
            messagebox.showerror("Account Locked", 
                "Too many failed password attempts. Application is locked for security.\n\n"
                "Please restart the application to try again.")
            return False
        else:
            # Show error with attempts remaining
            messagebox.showerror("Authentication Failed", 
                f"Invalid master password! {attempts_left} attempt{'s' if attempts_left > 1 else ''} remaining.")
            return False

# Function to navigate to the manage credentials page
def open_manage_page():
    home_frame.pack_forget()
    search_frame.pack_forget()
    manage_frame.pack(pady=20)
    display_credentials()

# Function to navigate to the search page
def open_search_page():
    home_frame.pack_forget()
    manage_frame.pack_forget()
    search_frame.pack(pady=20)

# Function to navigate to the home page
def go_home():
    manage_frame.pack_forget()
    search_frame.pack_forget()
    home_frame.pack(pady=20)
    search_entry.delete(0, tk.END)  # Clears the app name field
    search_result_label.config(text="")  # Clears search result
    copy_button.pack_forget()  # Hides the copy button
    search_email_entry.delete(0, tk.END)  # Clears the email entry field

# Function to generate a secure password
def generate_secure_password():
    app_name = entry_app_name.get()
    if not app_name:
        messagebox.showwarning("Input Error", "App name is required for password generation!")
        return
    
    seed = simpledialog.askstring("Seed Password", "Enter a simple seed password:")
    if seed:
        secure_pass = generate_password(seed, app_name, 12)
        entry_password.delete(0, tk.END)
        entry_password.insert(0, secure_pass)
        messagebox.showinfo("Password Generated", "A secure password has been generated!")

# Keep track of active clipboard clearing threads
clipboard_threads = []

# Variable to store the current password for copying
current_password_to_copy = ""

# Function to copy password to clipboard with auto-clear
def secure_copy_password(password, delay=10):
    global clipboard_threads
    
    # Clear any existing clipboard content
    root.clipboard_clear()
    
    # Copy the password to clipboard
    root.clipboard_append(password)
    root.update_idletasks()  # Force immediate update
    
    messagebox.showinfo("Copied", f"Password copied to clipboard! It will be cleared in {delay} seconds for security.")
    
    # Schedule direct clearing with Tkinter's after method
    root.after(delay * 1000, lambda: robust_clipboard_clear("Main view"))
    root.after((delay * 1000) + 500, lambda: double_check_clipboard())
    root.after((delay * 1000) + 1000, lambda: double_check_clipboard())
    
    # Emergency fallback
    def emergency_clear():
        try:
            root.clipboard_clear()
            root.clipboard_append("")
            root.update_idletasks()
            print("Emergency clipboard clear performed")
        except:
            pass
    
    root.after((delay * 1000) + 2000, emergency_clear)
    
    # Also use the thread approach as additional backup
    def clear_clipboard_thread():
        try:
            time.sleep(delay)
            root.after(0, lambda: root.clipboard_clear())
            root.after(0, lambda: root.update_idletasks())
            print("Thread-based clipboard cleared for security.")
        except Exception as e:
            print(f"Error in thread clearing clipboard: {e}")
    
    # Create thread as additional fallback
    clear_thread = threading.Thread(target=clear_clipboard_thread)
    clear_thread.daemon = True
    clear_thread.start()
    
    # Store a reference to the thread
    clipboard_threads.append(clear_thread)
    
    # Clean up completed threads
    clipboard_threads = [t for t in clipboard_threads if t.is_alive()]

# Function for robust clipboard clearing from any view
def robust_clipboard_clear(source="Unknown"):
    try:
        # Multiple approaches to clear clipboard
        root.clipboard_clear()
        root.clipboard_append("")
        root.update_idletasks()
        
        # Alternative approach
        root.clipboard_append(" ")
        root.clipboard_clear()
        root.update()
        
        print(f"Clipboard cleared from {source} for security.")
        messagebox.showinfo("Security Notice", "Clipboard has been cleared for security purposes.")
    except Exception as e:
        print(f"Error clearing clipboard from {source}: {e}")

# Function to search credentials by app name
def search_credential():
    user_email = search_email_entry.get()
    app_name = search_entry.get()
    
    if not app_name:
        messagebox.showwarning("Input Error", "App name is required!")
        return
    
    try:
        # First check if multiple accounts exist for this app
        if not user_email:
            # If email not provided, check if multiple accounts exist
            check_query = "SELECT DISTINCT user_email FROM credentials WHERE app_name = %s"
            cursor.execute(check_query, (app_name,))
            email_results = cursor.fetchall()
            
            if not email_results:
                messagebox.showwarning("Not Found", "No credentials found for this app.")
                search_result_label.config(text="")
                copy_button.pack_forget()
                return
                
            if len(email_results) > 1:
                # Multiple emails found, present them as options
                email_list = [email[0] for email in email_results]
                options = "\n".join([f"{i+1}. {email}" for i, email in enumerate(email_list)])
                
                # Create a dialog to select the email
                select_dialog = tk.Toplevel(root)
                select_dialog.title("Select Email")
                select_dialog.geometry("900x550")  # Standardized window size
                select_dialog.transient(root)
                select_dialog.grab_set()
                
                # Center the window
                select_dialog.update_idletasks()
                width = select_dialog.winfo_width()
                height = select_dialog.winfo_height()
                x = (select_dialog.winfo_screenwidth() // 2) - (width // 2)
                y = (select_dialog.winfo_screenheight() // 2) - (height // 2)
                select_dialog.geometry('{}x{}+{}+{}'.format(width, height, x, y))
                
                tk.Label(select_dialog, 
                         text=f"Multiple accounts found for {app_name}.\nPlease select an email:").pack(pady=10)
                
                listbox = tk.Listbox(select_dialog, width=50, height=10)
                listbox.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)
                
                for email in email_list:
                    listbox.insert(tk.END, email)
                
                def on_select():
                    if listbox.curselection():
                        index = listbox.curselection()[0]
                        selected_email = email_list[index]
                        # Update the email field
                        search_email_entry.delete(0, tk.END)
                        search_email_entry.insert(0, selected_email)
                        select_dialog.destroy()
                        # Call search again with the selected email
                        search_credential()
                
                tk.Button(select_dialog, text="Select", command=on_select, bg="#4CAF50", fg="white").pack(pady=10)
                return
            else:
                # Only one email found
                user_email = email_results[0][0]
                # Update the email field for clarity
                search_email_entry.delete(0, tk.END)
                search_email_entry.insert(0, user_email)
        
        # Continue with search using email and app name
        cursor.execute("SELECT * FROM credentials WHERE user_email = %s AND app_name = %s", (user_email, app_name))
        result = cursor.fetchone()
    
        if result:
            app_name_value = result[1]
            url_value = result[2]
            username_value = result[3]
            email_value = result[4]
            password_hash = result[5]
            is_encrypted = result[6] if len(result) > 6 else False
            
            search_result_label.config(text=f"App: {app_name_value}\nURL: {url_value}\nUsername: {username_value}\nEmail: {email_value}")
            
            # Store the password or hash in a global variable for the copy button
            global current_password_to_copy
            
            # If the password is encrypted, we need to verify master password before decrypting
            if is_encrypted:
                if verify_master_password():
                    try:
                        current_password_to_copy = decrypt_password(password_hash)
                        # Create a special copy function for the copied password
                        def copy_with_secure():
                            # Hide the button immediately before copying
                            copy_button.pack_forget()
                            search_result_label.config(text=search_result_label.cget("text") + "\n(Password copied to clipboard)")
                            secure_copy_password(current_password_to_copy)
                        
                        # Set command and display button
                        copy_button.config(command=copy_with_secure)
                        copy_button.pack(pady=5)
                    except Exception as e:
                        messagebox.showerror("Decryption Error", f"Could not decrypt password: {str(e)}")
                        copy_button.pack_forget()
                else:
                    # Master password verification failed
                    copy_button.pack_forget()
            else:
                # Legacy password - no decryption needed, but can't retrieve plaintext
                messagebox.showinfo("Legacy Password", "This password was stored with the old method and cannot be retrieved in plaintext. Please create a new password.")
                # For legacy passwords, still use the secure copy method
                current_password_to_copy = password_hash
                
                # Create a special copy function for legacy passwords
                def copy_legacy():
                    # Hide the button immediately before copying
                    copy_button.pack_forget()
                    search_result_label.config(text=search_result_label.cget("text") + "\n(Password hash copied to clipboard)")
                    secure_copy_password(current_password_to_copy)
                
                # Set command and display button
                copy_button.config(command=copy_legacy)
                copy_button.pack(pady=5)
        else:
            messagebox.showwarning("Not Found", f"No credentials found for {app_name} with email {user_email}.")
            search_result_label.config(text="")
            copy_button.pack_forget()
    except mysql.connector.Error as error:
        messagebox.showerror("Database Error", f"Error searching credentials: {str(error)}")
        search_result_label.config(text="")
        copy_button.pack_forget()

# Function to clear clipboard specifically for search page
def clear_clipboard_search():
    try:
        # Forcefully clear the clipboard multiple ways
        root.clipboard_clear()
        root.clipboard_append("")  # Replace with empty string
        root.update_idletasks()  # Force immediate update
        
        # Also try alternative approach
        root.clipboard_append(" ")  # Space character
        root.clipboard_clear()
        root.update()
        
        print("Search page clipboard cleared for security.")
        messagebox.showinfo("Security Notice", "Clipboard has been cleared for security purposes.")
    except Exception as e:
        print(f"Error clearing clipboard on search page: {e}")
        
    # Double-check after a short delay to ensure it's cleared
    root.after(500, double_check_clipboard)

# Additional function to double-check clipboard is cleared
def double_check_clipboard():
    try:
        # Ensure clipboard is still clear
        root.clipboard_clear()
        root.update_idletasks()
        print("Double-checked clipboard is cleared.")
    except Exception as e:
        print(f"Error in double-check clearing: {e}")

# Function to clear input fields
def clear_entries():
    entry_app_name.delete(0, tk.END)
    entry_url.delete(0, tk.END)
    entry_username.delete(0, tk.END)
    entry_user_email.delete(0, tk.END)
    entry_password.delete(0, tk.END)

# Function to display credentials
def display_credentials():
    try:
        ensure_connection()
        for row in tree.get_children():
            tree.delete(row)
        cursor.execute("SELECT id, app_name, url, username, user_email FROM credentials")
        for row in cursor.fetchall():
            tree.insert("", "end", values=row)
    except mysql.connector.Error as error:
        print(f"Error displaying credentials: {error}")
        messagebox.showerror("Database Error", f"Error retrieving credentials: {str(error)}")

# Function to add credentials
def add_credential():
    app_name = entry_app_name.get()
    url = entry_url.get()
    username = entry_username.get()
    user_email = entry_user_email.get()
    password = entry_password.get()
    
    # Validate inputs
    errors = validate_credential_inputs(app_name, url, user_email, password)
    if errors:
        messagebox.showwarning("Input Error", "\n".join(errors))
        return
    
    try:
        ensure_connection()
        # Encrypt the password before storing
        encrypted_password = encrypt_password(password)
        
        sql = "INSERT INTO credentials (app_name, url, username, user_email, password_hash, is_encrypted) VALUES (%s, %s, %s, %s, %s, %s)"
        cursor.execute(sql, (app_name, url, username, user_email, encrypted_password, True))
        conn.commit()
    
        messagebox.showinfo("Success", "Credential added successfully!")
        display_credentials()
        clear_entries()
    except mysql.connector.Error as error:
        print(f"Database error adding credential: {error}")
        messagebox.showerror("Database Error", f"Error adding credential: {str(error)}")
        try:
            conn.rollback()
        except:
            pass

# Function to edit credentials
def edit_credential():
    selected_item = tree.selection()
    if not selected_item:
        messagebox.showwarning("Selection Error", "No credential selected!")
        return
    
    # Get selected credential ID
    item = tree.item(selected_item)
    cred_id = item["values"][0]
    
    # Retrieve current values
    try:
        ensure_connection()
        cursor.execute("SELECT app_name, url, username, user_email FROM credentials WHERE id = %s", (cred_id,))
        current_values = cursor.fetchone()
        
        if not current_values:
            messagebox.showwarning("Error", "Could not retrieve credential data!")
            return
    except mysql.connector.Error as error:
        messagebox.showerror("Database Error", f"Error retrieving credential data: {str(error)}")
        return
    
    # Create edit window
    edit_window = tk.Toplevel(root)
    edit_window.title("Edit Credential")
    edit_window.geometry("900x550")  # Standardized window size
    edit_window.transient(root)
    edit_window.grab_set()
    
    # Create a frame for input fields
    entry_frame = tk.Frame(edit_window, bg="#f0f0f0")
    entry_frame.pack(pady=10, padx=20, fill="both")
    
    # Create entry fields in the edit window
    tk.Label(entry_frame, text="App Name:", bg="#f0f0f0").grid(row=0, column=0, padx=10, pady=5, sticky="w")
    edit_app_name = tk.Entry(entry_frame, width=30)
    edit_app_name.grid(row=0, column=1, padx=10, pady=5)
    edit_app_name.insert(0, current_values[0])
    
    tk.Label(entry_frame, text="URL:", bg="#f0f0f0").grid(row=1, column=0, padx=10, pady=5, sticky="w")
    edit_url = tk.Entry(entry_frame, width=30)
    edit_url.grid(row=1, column=1, padx=10, pady=5)
    edit_url.insert(0, current_values[1])
    
    tk.Label(entry_frame, text="Username:", bg="#f0f0f0").grid(row=2, column=0, padx=10, pady=5, sticky="w")
    edit_username = tk.Entry(entry_frame, width=30)
    edit_username.grid(row=2, column=1, padx=10, pady=5)
    if current_values[2]:  # Username might be NULL
        edit_username.insert(0, current_values[2])
    
    tk.Label(entry_frame, text="Email:", bg="#f0f0f0").grid(row=3, column=0, padx=10, pady=5, sticky="w")
    edit_user_email = tk.Entry(entry_frame, width=30)
    edit_user_email.grid(row=3, column=1, padx=10, pady=5)
    edit_user_email.insert(0, current_values[3])
    
    
    tk.Label(entry_frame, text="Password:", bg="#f0f0f0").grid(row=4, column=0, padx=10, pady=5, sticky="w")
    edit_password = tk.Entry(entry_frame, width=30, show="*")
    edit_password.grid(row=4, column=1, padx=10, pady=5)
    
    # Add notice about password
    password_notice = tk.Label(edit_window, text="Leave password empty to keep current password", fg="blue")
    password_notice.pack(pady=5)
    
    # Status label for error messages
    status_label = tk.Label(edit_window, text="", fg="red", bg="#f0f0f0")
    status_label.pack(pady=5)
    
    # Function to save edited values
    def save_edited():
        app_name = edit_app_name.get()
        url = edit_url.get()
        username = edit_username.get()
        user_email = edit_user_email.get()
        password = edit_password.get()
        
        # Validate inputs
        errors = validate_credential_inputs(app_name, url, user_email, password if password else "dummy")
        if errors and (password or "Password is required" not in errors):
            status_label.config(text="\n".join([e for e in errors if e != "Password is required"]))
            return
        
        # Clear any previous error message
        status_label.config(text="Saving changes...", fg="blue")
        edit_window.update()  # Force update to show message
        
        # Update query with or without password
        try:
            # Ensure we have a valid database connection
            if not ensure_connection():
                status_label.config(text="Database connection error. Please restart the application.", fg="red")
                return
                
            if password:
                # Encrypt the new password
                encrypted_password = encrypt_password(password)
                sql = """UPDATE credentials 
                        SET app_name = %s, url = %s, username = %s, user_email = %s, 
                        password_hash = %s, is_encrypted = TRUE
                        WHERE id = %s"""
                values = (app_name, url, username, user_email, encrypted_password, cred_id)
                print(f"Executing SQL with password: {sql} with values: {app_name}, {url}, {username}, {user_email}, [encrypted], {cred_id}")
            else:
                # Update without changing the password
                sql = """UPDATE credentials 
                        SET app_name = %s, url = %s, username = %s, user_email = %s 
                        WHERE id = %s"""
                values = (app_name, url, username, user_email, cred_id)
                print(f"Executing SQL without password: {sql} with values: {app_name}, {url}, {username}, {user_email}, {cred_id}")
            
            # Execute and commit
            cursor.execute(sql, values)
            conn.commit()
            
            print(f"Updated {cursor.rowcount} rows")
            
            if cursor.rowcount == 0:
                status_label.config(text=f"No changes made. ID {cred_id} not found.", fg="red")
                return
                
            # Success!
            messagebox.showinfo("Success", "Credential updated successfully!")
            edit_window.destroy()
            display_credentials()
        except mysql.connector.Error as error:
            error_msg = str(error)
            status_label.config(text=f"Database error: {error_msg}", fg="red")
            print(f"Database error: {error_msg}")
            
            # Try to rollback the transaction
            try:
                conn.rollback()
            except:
                pass
                
            # Try to reconnect if connection was lost
            try:
                if not conn.is_connected():
                    conn.reconnect()
                    status_label.config(text="Connection was lost. Reconnected. Please try again.", fg="orange")
            except:
                status_label.config(text="Database connection lost. Please restart the application.", fg="red")
    
    # Add save and cancel buttons
    btn_frame = tk.Frame(edit_window, bg="#f0f0f0")
    btn_frame.pack(pady=20)
    
    save_btn = tk.Button(btn_frame, text="Save Changes", command=save_edited, bg="#4CAF50", fg="white")
    save_btn.grid(row=0, column=0, padx=10)
    
    cancel_btn = tk.Button(btn_frame, text="Cancel", command=edit_window.destroy, bg="#f44336", fg="white")
    cancel_btn.grid(row=0, column=1, padx=10)

# Function to delete a credential
def delete_credential():
    selected_item = tree.selection()
    if not selected_item:
        messagebox.showwarning("Selection Error", "No credential selected!")
        return
    
    # Confirm deletion with user
    item = tree.item(selected_item)
    app_name = item["values"][1]  # App name is in the second column
    cred_id = item["values"][0]  # ID is in the first column
    
    confirm = messagebox.askyesno("Confirm Deletion", 
                                  f"Are you sure you want to delete the credential for '{app_name}'?",
                                  icon="warning")
    if not confirm:
        return
    
    try:
        ensure_connection()
        cursor.execute("DELETE FROM credentials WHERE id = %s", (cred_id,))
        conn.commit()
        
        if cursor.rowcount > 0:
            messagebox.showinfo("Success", "Credential deleted successfully!")
            display_credentials()
        else:
            messagebox.showwarning("Warning", f"No credential found with ID {cred_id}. It may have been already deleted.")
            display_credentials()
    except mysql.connector.Error as error:
        print(f"Error deleting credential: {error}")
        messagebox.showerror("Database Error", f"Error deleting credential: {str(error)}")
        try:
            conn.rollback()
        except:
            pass

# Show Password
def view_password():
    selected_item = tree.selection()
    if not selected_item:
        messagebox.showwarning("Selection Error", "No credential selected!")
        return
       
    item = tree.item(selected_item)
    cred_id = item["values"][0]
    
    # Get the password and check if it's encrypted
    cursor.execute("SELECT password_hash, is_encrypted FROM credentials WHERE id = %s", (cred_id,))
    result = cursor.fetchone()
    
    if result:
        password_value = result[0]
        is_encrypted = result[1] if len(result) > 1 else False
        
        if is_encrypted:
            # Verify master password before showing
            if verify_master_password():
                try:
                    decrypted_password = decrypt_password(password_value)
                    # Don't show the password in a dialog box for security
                    password_copied = messagebox.askyesno("Password Access", 
                        "Password is available. Would you like to copy it to clipboard?")
                    
                    if password_copied:
                        # Use the global variable to store the password and secure copy function
                        global current_password_to_copy
                        current_password_to_copy = decrypted_password
                        secure_copy_password(current_password_to_copy)
                except Exception as e:
                    messagebox.showerror("Decryption Error", f"Could not decrypt password: {str(e)}")
            else:
                messagebox.showerror("Access Denied", "Master password verification failed.")
        else:
            messagebox.showinfo("Legacy Password", 
                               "This password was stored with the old method and cannot be retrieved in plaintext. " 
                               "Please create a new password.")
    else:
        messagebox.showwarning("Not Found", "Password not found.")
    
def display_url():
    selected_item = tree.selection()
    if not selected_item:
        messagebox.showwarning("Selection Error", "No credential selected!")
        return
    
    item = tree.item(selected_item)
    cred_id = item["values"][0]
    
    cursor.execute("SELECT url FROM credentials WHERE id = %s", (cred_id,))
    result = cursor.fetchone()
    
    if result:
        url_value = result[0]
        pyperclip.copy(url_value)  # Copy URL to clipboard
        webbrowser.open(url_value)  # Open URL in the default web browser
        messagebox.showinfo("URL", f"URL opened in browser:\n{url_value}")
    else:
        messagebox.showwarning("Not Found", "URL not found.")

# Window closing handler
def on_closing():
    if messagebox.askokcancel("Quit", "Do you want to quit?"):
        # Close the database connection before exit
        if 'conn' in globals() and conn:
            cursor.close()
            conn.close()
        root.destroy()

root.protocol("WM_DELETE_WINDOW", on_closing)

def create_login_screen():
    """Create the initial login screen"""
    global failed_master_password_attempts, account_locked
    
    # Clear any existing widgets
    for widget in root.winfo_children():
        widget.destroy()
    
    # Configure the login screen
    root.title("Password Manager 4000 - Login")
    root.geometry("400x450")  # Standardized window size
    root.configure(bg="#f0f0f0")
    
    # Create main frame
    login_frame = tk.Frame(root, bg="#f0f0f0")
    login_frame.pack(pady=20, expand=True)
    
    # Logo
    logo_label = tk.Label(login_frame, image=logo_photo, bg="#f0f0f0")
    logo_label.pack(pady=20)
    
    # Welcome text
    tk.Label(login_frame, 
             text="Welcome to Password Manager 4000", 
             font=("Arial", 16), 
             bg="#f0f0f0").pack(pady=10)
    
    # Master password entry
    password_frame = tk.Frame(login_frame, bg="#f0f0f0")
    password_frame.pack(pady=20)
    
    tk.Label(password_frame, 
             text="Enter Master Password:", 
             bg="#f0f0f0").pack()
    
    password_entry = tk.Entry(password_frame, show="*")
    password_entry.pack(pady=5)
    
    # Status label for attempts and errors
    status_label = tk.Label(password_frame, text="", fg="red", bg="#f0f0f0")
    status_label.pack(pady=5)
    
    # Check if account is locked
    if account_locked:
        status_label.config(text="Account locked due to too many failed attempts.\nPlease restart the application.")
    
    def verify_login():
        global failed_master_password_attempts, account_locked
        
        # Check if account is locked
        if account_locked:
            messagebox.showerror("Account Locked", 
                "Too many failed attempts. Application is locked for security.\n\n"
                "Please restart the application to try again.")
            return
            
        password = password_entry.get()
        if password == SECRET_KEY:
            # Reset failed attempts counter on successful login
            failed_master_password_attempts = 0
            status_label.config(text="")
            # Reset cipher suite to ensure it uses the correct master password
            reset_cipher_suite()
            # Clear login screen
            login_frame.destroy()
            # Show main application
            create_main_app()
        else:
            # Increment failed attempts counter
            failed_master_password_attempts += 1
            
            # Calculate attempts remaining
            attempts_left = max_password_attempts - failed_master_password_attempts
            
            if attempts_left <= 0:
                # Lock the account if max attempts reached
                account_locked = True
                status_label.config(text="Account locked due to too many failed attempts.\nPlease restart the application.")
                messagebox.showerror("Account Locked", 
                    "Too many failed password attempts. Application is locked for security.\n\n"
                    "Please restart the application to try again.")
            else:
                # Show error with attempts remaining
                status_label.config(text=f"Invalid password! {attempts_left} attempt{'s' if attempts_left > 1 else ''} remaining.")
                messagebox.showerror("Login Failed", 
                    f"Invalid master password! {attempts_left} attempt{'s' if attempts_left > 1 else ''} remaining.")
                password_entry.delete(0, tk.END)
    
    # Login button
    login_btn = tk.Button(password_frame, 
              text="Login", 
              command=verify_login,
              bg="#4CAF50", 
              fg="white")
    login_btn.pack(pady=10)
    
    # Forgot password button
    forgot_btn = tk.Button(password_frame,
                text="Forgot Password",
                command=forgot_password_gui,
                bg="#3498db",
                fg="white")
    forgot_btn.pack(pady=5)

def forgot_password_gui():
    """GUI for password recovery via email"""
    global reset_token_value, recovery_password_frame
    reset_token_value = None
    recovery_password_frame = None
    
    # Create the recovery window
    recovery_window = tk.Toplevel(root)
    recovery_window.title("Password Recovery")
    recovery_window.geometry("900x550")  # Standardized window size
    recovery_window.transient(root)
    recovery_window.grab_set()
    
    # Create main frame
    main_frame = tk.Frame(recovery_window, bg="#f0f0f0")
    main_frame.pack(pady=20, padx=20, fill="both", expand=True)
    
    # Title
    title_label = tk.Label(main_frame, 
                          text="Master Password Recovery", 
                          font=("Arial", 16),
                          bg="#f0f0f0")
    title_label.pack(pady=10)
    
    # Instructions
    tk.Label(main_frame, 
             text="Enter your recovery email to receive a password reset code.",
             bg="#f0f0f0").pack(pady=10)
    
    # Email frame
    email_frame = tk.Frame(main_frame, bg="#f0f0f0")
    email_frame.pack(pady=10)
    
    tk.Label(email_frame, text="Recovery Email:", bg="#f0f0f0").grid(row=0, column=0, padx=10, pady=5, sticky="w")
    email_entry = tk.Entry(email_frame, width=30)
    email_entry.grid(row=0, column=1, padx=10, pady=5)
    
    # Status label
    status_label = tk.Label(main_frame, text="", fg="red", bg="#f0f0f0")
    status_label.pack(pady=5)
    
    # Token entry frame (hidden initially)
    token_frame = tk.Frame(main_frame, bg="#f0f0f0")
    
    tk.Label(token_frame, text="Reset Code:", bg="#f0f0f0").grid(row=0, column=0, padx=10, pady=5, sticky="w")
    token_entry = tk.Entry(token_frame, width=30)
    token_entry.grid(row=0, column=1, padx=10, pady=5)
    
    # Function to handle password reset
    def set_new_password(password_entry, confirm_entry, reset_btn):
        new_password = password_entry.get()
        confirm = confirm_entry.get()
        
        # Validate passwords
        if not new_password:
            status_label.config(text="Password cannot be empty.", fg="red")
            return
            
        if len(new_password) < 8:
            status_label.config(text="Password must be at least 8 characters.", fg="red")
            return
            
        if new_password != confirm:
            status_label.config(text="Passwords do not match.", fg="red")
            return
    
        # Disable the button during processing
        reset_btn.config(state=tk.DISABLED)
        
        # Get the recovery email
        recovery_email = email_entry.get().strip()
        
        # Run the reset in a separate thread to keep the UI responsive
        def process_reset():
            result = reset_password_with_progress(recovery_email, reset_token_value, new_password, status_label)
            
            # Update UI based on result
            if result:
                status_label.config(text="Master password reset successfully!", fg="green")
                
                # Updated message to reflect that passwords will remain accessible
                messagebox.showinfo(
                    "Password Reset Complete", 
                    "Your master password has been changed successfully.\n\n"
                    "All your stored passwords have been safely re-encrypted with your new master password.\n"
                    "You will be able to access them normally after logging in with your new password.\n\n"
                    "This process was secured using email verification to ensure only you could authorize this change."
                )
                
                # Remove all frames and show success message
                recovery_password_frame.pack_forget()
                
                success_frame = tk.Frame(main_frame, bg="#f0f0f0")
                success_frame.pack(pady=10)
                
                tk.Label(success_frame, 
                        text="Your master password has been reset.\nAll stored passwords have been re-encrypted.\nYou can now log in with your new password.",
                        bg="#f0f0f0").pack(pady=10)
                
                # Replace button with close button
                tk.Button(success_frame, 
                        text="Close program", 
                        command=root.destroy,
                        bg="#4CAF50", 
                        fg="white").pack(pady=10)
            else:
                status_label.config(text="Failed to reset master password. Please try again.", fg="red")
                reset_btn.config(state=tk.NORMAL)
        
        # Start the reset process in a separate thread
        threading.Thread(target=process_reset).start()
    
    # Function to verify reset code
    def verify_reset_code():
        token = token_entry.get().strip()
        
        if not token:
            status_label.config(text="Please enter the reset code.", fg="red")
            return
            
        # Verify the token
        if token != reset_token_value:
            status_label.config(text="Invalid reset code. Please try again.", fg="red")
            return
            
        # Token is valid - show password entry
        token_frame.pack_forget()
        send_btn.pack_forget()
        
        # Show password entry frame
        global recovery_password_frame
        recovery_password_frame = tk.Frame(main_frame, bg="#f0f0f0")
        recovery_password_frame.pack(pady=10)
        
        tk.Label(recovery_password_frame, text="New Master Password:", bg="#f0f0f0").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        password_entry = tk.Entry(recovery_password_frame, show="*", width=30)
        password_entry.grid(row=0, column=1, padx=10, pady=5)
        
        tk.Label(recovery_password_frame, text="Confirm Password:", bg="#f0f0f0").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        confirm_entry = tk.Entry(recovery_password_frame, show="*", width=30)
        confirm_entry.grid(row=1, column=1, padx=10, pady=5)
        
        # Reset button
        reset_btn = tk.Button(recovery_password_frame, 
                             text="Reset Password", 
                             command=lambda: set_new_password(password_entry, confirm_entry, reset_btn),
                             bg="#4CAF50", 
                             fg="white")
        reset_btn.grid(row=2, column=0, columnspan=2, pady=10)
        
        status_label.config(text="Reset code verified. Please enter a new master password.", fg="green")
    
    # Function to send reset code
    def send_reset_code():
        global reset_token_value
        recovery_email = email_entry.get().strip()
        
        if not recovery_email:
            status_label.config(text="Please enter your recovery email.", fg="red")
            return
            
        if not is_valid_email(recovery_email):
            status_label.config(text="Please enter a valid email address.", fg="red")
            return
        
        # Check if this is a verified recovery email
        from database_manager import get_recovery_email
        registered_email = get_recovery_email()
        
        if not registered_email or registered_email != recovery_email:
            status_label.config(text="This email is not registered for recovery.", fg="red")
            return
            
        # Initiate password reset
        status_label.config(text="Sending reset code...", fg="blue")
        
        # Update UI while processing
        recovery_window.update()
        
        from database_manager import initiate_password_reset, send_reset_email
        success, reset_token = initiate_password_reset(recovery_email)
        
        if not success:
            status_label.config(text=f"Error: {reset_token}", fg="red")
            return
            
        # Send reset email
        send_reset_email(recovery_email, reset_token)
        
        # Store the reset token for verification
        reset_token_value = reset_token
        
        # Show token entry
        status_label.config(text="Reset code sent! Check your email and enter the code below.", fg="green")
        token_frame.pack(pady=10)
        
        # Change button to verify code
        send_btn.config(text="Verify Code", command=verify_reset_code)
    
    # Send reset code button
    send_btn = tk.Button(main_frame, 
                       text="Send Reset Code",
                       command=send_reset_code, 
                       bg="#4CAF50", 
                       fg="white")
    send_btn.pack(pady=10)
    
    # Close button
    close_btn = tk.Button(main_frame, 
                         text="Close",
                         command=recovery_window.destroy, 
                         bg="#f44336", 
                         fg="white")
    close_btn.pack(pady=10)

def reset_password_with_progress(recovery_email, reset_token_value, new_password, status_label):
    """Reset the master password with progress updates"""
    # Show that password reset is in progress
    status_label.config(text="Resetting master password and re-encrypting stored passwords...", fg="blue")
    status_label.update()
    
    # Process the reset - this will now decrypt and re-encrypt all stored passwords
    result = reset_master_password(recovery_email, reset_token_value, new_password)
    
    if result:
        status_label.config(text="Master password reset successfully!", fg="green")
        # Add a success message
        import tkinter.messagebox as messagebox
        messagebox.showinfo(
            "Password Reset Complete", 
            "Your master password has been changed successfully.\n\n"
            "All your stored passwords have been securely re-encrypted with your new master password "
            "and should be fully accessible when you log in.\n\n"
            "This process was secured using email verification to ensure only you could authorize "
            "this change."
        )
    else:
        status_label.config(text="Failed to reset master password. Please try again.", fg="red")
        # Add a failure message with more details
        import tkinter.messagebox as messagebox
        messagebox.showerror(
            "Password Reset Failed", 
            "There was an error while resetting your master password.\n\n"
            "Please check the error messages displayed in the console for more details."
        )
    
    return result

def setup_recovery_gui():
    """Set up email-based recovery using GUI"""
    # Create a new window
    recovery_window = tk.Toplevel(root)
    recovery_window.title("Setup Password Recovery")
    recovery_window.geometry("900x550")  # Standardized window size
    recovery_window.configure(bg="#f0f0f0")
    
    # Center the window
    recovery_window.update_idletasks()
    width = recovery_window.winfo_width()
    height = recovery_window.winfo_height()
    x = (recovery_window.winfo_screenwidth() // 2) - (width // 2)
    y = (recovery_window.winfo_screenheight() // 2) - (height // 2)
    recovery_window.geometry('{}x{}+{}+{}'.format(width, height, x, y))
    
    # Create main frame
    main_frame = tk.Frame(recovery_window, bg="#f0f0f0")
    main_frame.pack(pady=20, padx=20, fill="both", expand=True)
    
    # Title
    title_label = tk.Label(main_frame, text="Setup Password Recovery", 
                         font=("Arial", 16, "bold"), bg="#f0f0f0")
    title_label.pack(pady=10)
    
    # Always create email frame
    email_frame = tk.Frame(main_frame, bg="#f0f0f0")
    
    # Status label - create early so it can be referenced
    status_label = tk.Label(main_frame, text="", fg="red", bg="#f0f0f0")
    status_label.pack(pady=10)
    
    # Store the current recovery email and if email change is active
    current_recovery_email = None
    email_change_active = False
    
    # Check if recovery email is already set up
    recovery_email = get_recovery_email()
    if recovery_email:
        current_recovery_email = recovery_email
        tk.Label(main_frame, 
                text=f"Recovery email is already set up: {recovery_email}",
                bg="#f0f0f0").pack(pady=10)
        
        def change_email():
            nonlocal email_change_active
            email_change_active = True
            email_frame.pack(pady=10)
            status_label.config(text="")
        
        change_btn = tk.Button(main_frame, text="Change Recovery Email",
                             command=change_email, bg="#4CAF50", fg="white")
        change_btn.pack(pady=5)
    else:
        # If no recovery email is set up, show the email frame immediately
        email_change_active = True
        email_frame.pack(pady=10)
    
    # Email entry
    tk.Label(email_frame, text="Enter Recovery Email:", bg="#f0f0f0").pack()
    email_entry = tk.Entry(email_frame, width=40)
    email_entry.pack(pady=5)
    
    # Add example text
    example_label = tk.Label(email_frame, text="Example: user@example.com", 
                           fg="gray", bg="#f0f0f0", font=("Arial", 9))
    example_label.pack()
    
    # Verification code entry (initially hidden)
    code_frame = tk.Frame(main_frame, bg="#f0f0f0")
    code_label = tk.Label(code_frame, text="Enter Verification Code:", bg="#f0f0f0")
    code_label.pack()
    code_entry = tk.Entry(code_frame, width=20, show="*")
    code_entry.pack(pady=5)
    
    def send_verification():
        nonlocal email_change_active, current_recovery_email
        
        # Determine which email to use
        if email_change_active:
            # User is entering a new email
            email = email_entry.get().strip()
        if not email:
                status_label.config(text="Please enter an email address")
                return
             
        if not is_valid_email(email):
                status_label.config(text="Invalid email format. Please use format: user@example.com")
                return 
        
            # No app password required anymore, even when changing email
        else:
            # Use the existing recovery email
            email = current_recovery_email
        
        status_label.config(text="Processing...", fg="blue")
        recovery_window.update()  # Force update to show processing message
        
        # Register recovery email and get verification code
        success, verification_code = register_recovery_email(email)
        if not success:
            status_label.config(text=f"Failed to set up recovery email: {verification_code}")
            return
        
        # Send verification email appropriately
        try:
            # Send verification email without app password
            print(f"Sending verification code to {email}")
            send_verification_email(email, verification_code)
            
            # Show verification code entry
            code_frame.pack(pady=10)
            status_label.config(text=f"Verification code sent to {email}. Please check your inbox.", fg="blue")
        except Exception as e:
            # Handle exceptions from email sending
            print(f"Error in send_verification: {e}")
            messagebox.showinfo("Verification Code", 
                              f"Could not send email but verification code is: {verification_code}\n\n"
                              f"Please use this code to verify your email.")
            # Show verification code entry even if email fails
            try:
                code_frame.pack(pady=10)
                status_label.config(text=f"Verification code displayed. Please enter it below.", fg="blue")
            except Exception as ui_error:
                print(f"UI error: {ui_error}")
                # Last resort: show the code in a messagebox
                messagebox.showinfo("Verification Code", f"Your verification code is: {verification_code}")
        
    def verify_code():
        code = code_entry.get().strip()
        if not code:
            status_label.config(text="Please enter the verification code")
            
            # Show verifying status
            status_label.config(text="Verifying code...", fg="blue")
            recovery_window.update()  # Force update to show the message
            
            # Get the email being verified
            email_to_verify = email_entry.get().strip() if email_change_active else current_recovery_email
            
            # Call verify function with proper parameters
            if verify_recovery_email(email_to_verify, code):
                old_email = current_recovery_email
                
                # Get the latest verified email after verification
                new_email = get_recovery_email()
                
                if old_email and old_email != new_email:
                    status_label.config(text=f"Recovery email changed from {old_email} to {new_email}!", fg="green")
                else:
                    status_label.config(text=f"Email {new_email} verified successfully!", fg="green")
                
                # Add a delay before closing the window
                recovery_window.after(2500, recovery_window.destroy)
        else:
                status_label.config(text="Invalid verification code or verification failed. Please try again.", fg="red")
        
    # Add verify button
    verify_btn = tk.Button(code_frame, text="Verify Code",
                        command=verify_code, bg="#4CAF50", fg="white")
    verify_btn.pack(pady=5)
    
    # Add send verification button
    send_btn = tk.Button(main_frame, text="Send Verification Code",
                        command=send_verification, bg="#4CAF50", fg="white")
    send_btn.pack(pady=10)
    
    # Close button
    close_btn = tk.Button(main_frame, text="Close",
                         command=recovery_window.destroy, bg="#f44336", fg="white")
    close_btn.pack(pady=10)

def main():
    # Set up window closing handler
    root.protocol("WM_DELETE_WINDOW", on_closing)
    
    # Create the main application UI and start it
    create_login_screen()
    root.mainloop()

if __name__ == "__main__":
    main()
