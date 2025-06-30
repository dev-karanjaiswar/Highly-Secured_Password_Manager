# Password Manager 4000

A secure password management system with both GUI and CLI interfaces.

## Project Structure

```
.venv
pw-master/
    |               
    ├── app.py           # Main GUI application
    ├── background.jpg   # Background image for GUI
    |── logo.jpg         # Logo image for GUI
    ├── configure_email.py    # Email configuration utilities
    ├── database_manager.py   # Database operations
    ├── hash_maker.py         # Password hashing functions
    ├── menu.py               # CLI menu system
    ├── mfa.py                # Multi-factor authentication
    ├── password_manager.py   # Core password management logic
    ├── reset_database.py     # Database reset utilities
    ├── secret.py             # Secret key management
    └── ui_theme.py           # Terminal UI styling
__init__.py          # Package initialization
main.py              # Main entry point
requirements.txt     # Dependencies
```

## Installation

1. Clone the repository:
   ```
   git clone <repository-url>
   cd pw-master
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Set up the MySQL database:
   - Create a database named `password_manager`
   - Run the SQL schema (included in documentation)

## Usage

### GUI Mode

```
python app.py --gui
```

### CLI Mode

```
python password_manager.py --cli
```

## Features

- Secure password storage with strong encryption
- Password generation
- Two-factor authentication
- Email-based account recovery
- Both GUI and CLI interfaces
- Master password 
- User friendly ui


## Security Notes

- All passwords are salted hash and then encrypted using AES-256
- Master password is never stored, only a salted hash which is then encrypted using AES-256
- Recovery options include security questions and email verification
- Password reset tokens expire after 15 minutes
- Verification codes expire after 30 minutes 