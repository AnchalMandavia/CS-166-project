import time
import hmac
import hashlib
import base64
from typing import Tuple

# Function to generate the OTP
def generate_otp(secret: str) -> str:
    """
    Generate a 6-digit OTP using TOTP algorithm.

    :param secret: The shared secret key for OTP generation.
    :return: A 6-digit OTP as a string.
    """
    # Get the current time in 30-second intervals
    interval = int(time.time()) // 30

    # Convert the interval to bytes
    interval_bytes = interval.to_bytes(8, byteorder='big')

    # Decode the secret key from Base32
    secret_bytes = base64.b32decode(secret.upper())

    # Generate the HMAC hash
    hmac_hash = hmac.new(secret_bytes, interval_bytes, hashlib.sha1).digest()

    # Extract dynamic offset from the hash
    offset = hmac_hash[-1] & 0x0F

    # Get a 4-byte code from the hash starting at the offset
    code = hmac_hash[offset:offset + 4]

    # Convert the code to an integer
    code_int = int.from_bytes(code, byteorder='big') & 0x7FFFFFFF

    # Generate a 6-digit OTP
    otp = code_int % 1000000

    return f"{otp:06d}"

# Function to verify the OTP
def verify_otp(user_otp: str, secret: str) -> bool:
    """
    Verify if the provided OTP matches the generated OTP.

    :param user_otp: The OTP entered by the user.
    :param secret: The shared secret key for OTP generation.
    :return: True if OTP matches, False otherwise.
    """
    generated_otp = generate_otp(secret)
    return user_otp == generated_otp

# Main function to simulate the authentication process
def main():
    """
    Simulate an authentication app with OTP verification.
    """
    # Shared secret key (in a real application, this would be unique per user)
    secret = "JBSWY3DPEHPK3PXP"  # Example Base32 encoded secret key

    print("\n=== Authentication App Simulator ===")
    print("Please use your authenticator app to generate an OTP.")

    while True:
        print("\n--- Authentication Menu ---")
        print("1. Generate OTP (for testing purposes)")
        print("2. Verify OTP")
        print("3. Exit")
        
        choice = input("Choose an option (1/2/3): ")

        if choice == "1":
            otp = generate_otp(secret)
            print(f"Generated OTP (valid for 30 seconds): {otp}")

        elif choice == "2":
            user_otp = input("Enter the OTP: ")
            if verify_otp(user_otp, secret):
                print("Access Granted!")
            else:
                print("Invalid OTP. Access Denied.")

        elif choice == "3":
            print("Exiting the application. Goodbye!")
            break

        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main()