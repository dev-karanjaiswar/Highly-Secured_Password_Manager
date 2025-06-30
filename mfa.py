import random
import string
import time
from datetime import datetime, timedelta
from secret import get_secret_key, load_env_file

load_env_file()  # Load environment variables from .env file    
# Default phone number
DEFAULT_PHONE = "+919324615915"  # User's actual WhatsApp number

# Function to generate a random OTP
def generate_otp(length=6):
    """Generate a random OTP of specified length."""
    # Using only digits for OTP
    otp = ''.join(random.choices(string.digits, k=length))
    return otp

# Function to verify OTP
def verify_otp(stored_otp, user_input):
    """Verify if the entered OTP matches the generated one."""
    return stored_otp == user_input

# Main MFA function for command-line interface
def perform_mfa_verification(phone_number=DEFAULT_PHONE):
    """Complete MFA verification process with simplified implementation."""
    # Generate OTP
    otp = generate_otp()
    
    # Make the verification code EXTREMELY visible
    print("\n")
    print("="*60)
    print("               MFA VERIFICATION CODE                  ")
    print("="*60)
    print(f"YOUR VERIFICATION CODE IS: {otp}")
    print(f"PHONE NUMBER: {phone_number}")
    print("="*60)
    print("\n")
    
    # Ask user to enter OTP
    user_otp = input("Enter the verification code shown above: ")
    
    # Verify OTP
    if verify_otp(otp, user_otp):
        print("MFA verification successful!")
        return True
    else:
        print("Invalid OTP. MFA verification failed.")
        # Show the correct code for debugging purposes
        print(f"Expected: {otp}, Received: {user_otp}")
        return False

# Main MFA function for GUI interface
def prepare_mfa_verification(phone_number=DEFAULT_PHONE):
    """Prepare MFA verification for GUI."""
    # Generate OTP
    otp = generate_otp()
    
    # Make the verification code extremely visible in console for demo purposes
    print("\n")
    print("="*60)
    print("               GUI MFA VERIFICATION CODE              ")
    print("="*60)
    print(f"YOUR VERIFICATION CODE IS: {otp}")
    print(f"PHONE NUMBER: {phone_number}")
    print("="*60)
    print("\n")
    
    # Return a verification function
    def verify(user_input):
        result = verify_otp(otp, user_input)
        if not result:
            # Debug output
            print(f"Expected: {otp}, Received: {user_input}")
        return result
    
    return otp, verify

# Test the MFA system if run directly
if __name__ == "__main__":
    # Use the default phone number for testing
    print("Testing MFA module...")
    perform_mfa_verification() 