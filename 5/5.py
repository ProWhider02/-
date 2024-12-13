import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# Secret key for JWT
SECRET_KEY = "your_secret_key"

# User database
users = {
    "test_user": generate_password_hash("password123")
}

def login():
    username = input("Enter username: ")
    password = input("Enter password: ")

    user_password_hash = users.get(username)
    if not user_password_hash or not check_password_hash(user_password_hash, password):
        print("Invalid username or password.")
        return None

    # Generate JWT token
    token = jwt.encode({
        "username": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, SECRET_KEY, algorithm="HS256")

    print(f"Login successful! Your token: {token}")
    return token

def protected(token):
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        print(f"Access granted! Welcome, {decoded['username']}.")
    except jwt.ExpiredSignatureError:
        print("Token has expired.")
    except jwt.InvalidTokenError:
        print("Invalid token.")

if __name__ == "__main__":
    print("=== Welcome ===")
    token = login()
    if token:
        print("Accessing protected resource...")
        protected(token)
