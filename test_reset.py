import database_manager as db
from secret import get_secret_key, set_env_password

def test_reset():
    """Test the master password reset functionality directly"""
    print("Current master password:", get_secret_key())
    
    # Get the verified recovery email
    recovery_email = db.get_recovery_email()
    if not recovery_email:
        print("No verified recovery email found. Please set up recovery email first.")
        return
    
    print(f"Found recovery email: {recovery_email}")
    
    # Generate a reset token
    success, token = db.initiate_password_reset(recovery_email)
    if not success:
        print(f"Failed to initiate password reset: {token}")
        return
        
    print(f"Reset token generated: {token}")
    
    # Test the reset function
    new_password = "newpassword123"
    print(f"Attempting to reset password to: {new_password}")
    
    result = db.reset_master_password(recovery_email, token, new_password)
    
    if result:
        print("Password reset successful!")
        print("New master password:", get_secret_key())
    else:
        print("Password reset FAILED!")
        
    print("Test completed.")

if __name__ == "__main__":
    test_reset() 