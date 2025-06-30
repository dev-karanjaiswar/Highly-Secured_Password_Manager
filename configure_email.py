import tkinter as tk
from tkinter import messagebox, ttk
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from secret import load_env_file

load_env_file()  # Load environment variables from .env file

def configure_email_settings():
    """Configure email settings through a GUI interface"""
    # Create the main window
    root = tk.Tk()
    root.title("Email Configuration")
    root.geometry("900x550")  # Standardized window size
    root.configure(bg="#f0f0f0")
    
    # Center the window
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry('{}x{}+{}+{}'.format(width, height, x, y))
    
    # Create main frame
    main_frame = tk.Frame(root, bg="#f0f0f0")
    main_frame.pack(pady=20, padx=20, fill="both", expand=True)
    
    # Title
    title_label = tk.Label(main_frame, text="Email Configuration", 
                         font=("Arial", 16, "bold"), bg="#f0f0f0")
    title_label.pack(pady=10)
    
    # Instructions
    instructions = """
    Configure your email settings for password recovery.
    For Gmail users:
    1. Enable 2-Step Verification in your Google Account
    2. Generate an App Password:
       - Go to Google Account Settings
       - Security > 2-Step Verification > App passwords
       - Select "Mail" and your device
       - Use the generated 16-character password
    """
    instructions_label = tk.Label(main_frame, text=instructions, 
                                font=("Arial", 10), bg="#f0f0f0", 
                                wraplength=400, justify="left")
    instructions_label.pack(pady=10)
    
    # Form frame
    form_frame = tk.Frame(main_frame, bg="#f0f0f0")
    form_frame.pack(pady=10, fill="x")
    
    # SMTP Server
    tk.Label(form_frame, text="SMTP Server:", bg="#f0f0f0").grid(row=0, column=0, padx=5, pady=5, sticky="w")
    smtp_server = tk.Entry(form_frame, width=30)
    smtp_server.grid(row=0, column=1, padx=5, pady=5)
    smtp_server.insert(0, os.getenv("PM_SMTP_SERVER", "smtp.gmail.com"))
    
    # SMTP Port
    tk.Label(form_frame, text="SMTP Port:", bg="#f0f0f0").grid(row=1, column=0, padx=5, pady=5, sticky="w")
    smtp_port = tk.Entry(form_frame, width=30)
    smtp_port.grid(row=1, column=1, padx=5, pady=5)
    smtp_port.insert(0, os.getenv("PM_SMTP_PORT", "587"))
    
    # Email Address
    tk.Label(form_frame, text="Email Address:", bg="#f0f0f0").grid(row=2, column=0, padx=5, pady=5, sticky="w")
    email_address = tk.Entry(form_frame, width=30)
    email_address.grid(row=2, column=1, padx=5, pady=5)
    email_address.insert(0, os.getenv("PM_SMTP_USER", ""))
    
    # Password/App Password
    tk.Label(form_frame, text="Password/App Password:", bg="#f0f0f0").grid(row=3, column=0, padx=5, pady=5, sticky="w")
    password = tk.Entry(form_frame, width=30, show="*")
    password.grid(row=3, column=1, padx=5, pady=5)
    password.insert(0, os.getenv("PM_SMTP_PASSWORD", ""))
    
    # Status label
    status_label = tk.Label(main_frame, text="", fg="red", bg="#f0f0f0")
    status_label.pack(pady=10)
    
    def test_email():
        """Test the email configuration"""
        try:
            # Get values
            server = smtp_server.get().strip()
            port = int(smtp_port.get().strip())
            user = email_address.get().strip()
            pwd = password.get().strip()
            
            if not all([server, port, user, pwd]):
                status_label.config(text="Please fill in all fields")
                return
            
            # Create test message
            msg = MIMEMultipart()
            msg['From'] = user
            msg['To'] = user
            msg['Subject'] = "Password Manager 4000 - Test Email"
            
            body = "This is a test email from Password Manager 4000."
            msg.attach(MIMEText(body, 'plain'))
            
            # Try to send
            with smtplib.SMTP(server, port) as server:
                server.starttls()
                server.login(user, pwd)
                server.send_message(msg)
            
            status_label.config(text="Test email sent successfully!", fg="green")
            
        except Exception as e:
            status_label.config(text=f"Error: {str(e)}")
    
    def save_settings():
        """Save the email configuration"""
        try:
            # Get values
            server = smtp_server.get().strip()
            port = smtp_port.get().strip()
            user = email_address.get().strip()
            pwd = password.get().strip()
            
            if not all([server, port, user, pwd]):
                status_label.config(text="Please fill in all fields")
                return
            
            # Update .env file
            env_path = os.path.join(os.path.dirname(__file__), ".env")
            env_lines = []
            
            # Read existing .env file if it exists
            if os.path.exists(env_path):
                with open(env_path, 'r') as f:
                    env_lines = f.readlines()
            
            # Update or add email settings
            settings = {
                "PM_SMTP_SERVER": server,
                "PM_SMTP_PORT": port,
                "PM_SMTP_USER": user,
                "PM_SMTP_PASSWORD": pwd
            }
            
            for key, value in settings.items():
                found = False
                for i, line in enumerate(env_lines):
                    if line.startswith(f"{key}="):
                        env_lines[i] = f"{key}={value}\n"
                        found = True
                        break
                if not found:
                    env_lines.append(f"{key}={value}\n")
            
            # Write back to .env file
            with open(env_path, 'w') as f:
                f.writelines(env_lines)
            
            # Set environment variables
            os.environ["PM_SMTP_SERVER"] = server
            os.environ["PM_SMTP_PORT"] = port
            os.environ["PM_SMTP_USER"] = user
            os.environ["PM_SMTP_PASSWORD"] = pwd
            
            status_label.config(text="Settings saved successfully!", fg="green")
            
        except Exception as e:
            status_label.config(text=f"Error saving settings: {str(e)}")
    
    # Button frame
    button_frame = tk.Frame(main_frame, bg="#f0f0f0")
    button_frame.pack(pady=10)
    
    # Test button
    test_button = tk.Button(button_frame, text="Test Email", command=test_email,
                          bg="#4CAF50", fg="white", font=("Arial", 12), width=15)
    test_button.pack(side="left", padx=5)
    
    # Save button
    save_button = tk.Button(button_frame, text="Save Settings", command=save_settings,
                          bg="#2196F3", fg="white", font=("Arial", 12), width=15)
    save_button.pack(side="left", padx=5)
    
    # Close button
    close_button = tk.Button(button_frame, text="Close", command=root.destroy,
                           bg="#f44336", fg="white", font=("Arial", 12), width=15)
    close_button.pack(side="left", padx=5)
    
    # Start the application
    root.mainloop()

if __name__ == "__main__":
    configure_email_settings() 