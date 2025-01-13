import json
import bcrypt
import secrets
from datetime import datetime, timedelta

USER_INFO_FILE = 'user_info.json'
ATTEMPT_LIMIT = 5
LOCK_TIME = timedelta(minutes=15)


def load_user_info():
    try:
        with open(USER_INFO_FILE, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        print("User log file not found. Creating a new one.")
        return {}
    except json.JSONDecodeError:
        print("Error decoding user log file. Initializing with empty log.")
        return {}


def save_user_info(user_logs):
    with open(USER_INFO_FILE, 'w') as file:
        json.dump(user_logs, file, indent=4)


def is_valid_password(password):
    if len(password) < 8:
        return False
    if not any(char.isdigit() for char in password):
        return False
    if not any(char.isupper() for char in password):
        return False
    if not any(char.islower() for char in password):
        return False
    if not any(char.isalnum() for char in password):
        return False
    return True


def has_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def check_password(password, hashed_password):
    return bcrypt.checkpw(password.encode(), hashed_password.encode())


def generate_token(user_id):
    return secrets.token_urlsafe(16)


def create_account(user_logs):
    print("****************************")
    print("Creating account")
    username = input("Enter your username: ").lower()
    if username in user_logs:
        print("Username already exists")
        return
    while True:
        print("*********************************")
        password = input("Enter your password: ")
        if not is_valid_password(password):
            print("*********************************************************")
            print(
                "Invalid password. Password must be at least 8 characters long and include at least one uppercase "
                "letter,"
                "one lowercase letter, one number, and one special character.")
        else:
            print("**********************************************")
            confirm_password = input("confirm your password: ")
            if password != confirm_password:
                print("******************************************")
                print("password does not match!!")
            else:
                hashed_password = has_password(password)
                print("**************************************")
                name = input("Enter your first name: ")
                last_name = input("Enter your last name: ")
                phone = input("Enter your phone number: ")
                email = input("Enter your email address: ")
                print("******************************************")
                print("Almost there \n Please enter your security answers ")
                print("***********************************************")
                quiz1 = input("Which city were you born in? ")
                quiz2 = input("What is your nickname? ")
                quiz3 = input("What is your pet's name? ")
                user_logs[username] = {
                    "name": name,
                    "last_name": last_name,
                    "emai": email,
                    "phone": phone,
                    "password": hashed_password,
                    "failed_attempts": 0,
                    "lock_until": None,
                    "quiz1": quiz1,
                    "quiz2": quiz2,
                    "quiz3": quiz3,
                }
                save_user_info(user_logs)
                print("******************************************")
                print("Your account has been created")
                break


def login(user_logs):
    print("Logging in...")
    username = input("Enter your username: ").lower()
    if username not in user_logs:
        print("Username does not exist.")
        return None
    user_data = user_logs[username]
    if user_data["lock_until"]:
        lock_until = datetime.strptime(user_data["lock_until"], "%Y-%m-%d %H:%M:%S")
        if datetime.now() < lock_until:
            print(f"Account locked. Try again after {lock_until}.")
            return None
        else:
            user_data["failed_attempts"] = 0
            user_data["lock_until"] = None
    while True:
        pwd = input("Enter your password: ")
        if not check_password(user_data['password'], pwd):
            user_data["failed_attempts"] += 1
            if user_data["failed_attempts"] >= ATTEMPT_LIMIT:
                user_data["lock_until"] = (datetime.now() + LOCK_TIME).strftime("%Y-%m-%d %H:%M:%S")
                print(f"Account locked due to too many faild attempts. Try again after {user_data['lock_until']}.")
                save_user_info(user_logs)
                return None
            else:
                print(f"Password does not match. {ATTEMPT_LIMIT - user_data['failed_attempts']} attempts left.")
        else:
            user_data["failed_attempts"] = 0
            user_data["lock_until"] = None
            print(f"Welcome back, {username}!")
            save_user_info(user_logs)
            return username


def reset_password(user_logs, username, user_data):
    print("**********************************")
    print("Resetting password...")
    while True:
        new_password = input("Enter your new password: ")
        confirm_password = input("Confirm your new password: ")
        if not is_valid_password(new_password):
            print("**********************************")
            print(
                "Invalid password. Password must be at least 8 characters long and include at least one uppercase "
                "letter, one lowercase letter, one number, and one special character.")
        elif new_password != confirm_password:
            print("**************************************")
            print("Password does not match!")
        elif check_password(user_data['password'], new_password):
            print("**********************************")
            print("New password cannot be the same as the old password!")
        else:
            hashed_password = has_password(new_password)
            user_data["password"] = hashed_password
            user_data["failed_attempts"] = 0
            user_data["lock_until"] = None
            save_user_info(user_logs)
            print("*************************")
            print("Password reset successfully!!")
            return


def request_password_reset(user_logs):
    print("************************************")
    print("Requesting password reset...")
    username = input("Enter your username: ")
    if username not in user_logs:
        print("**************************************")
        print("Username does not exist!!")
        return
    user_data = user_logs[username]
    print("***************************************")
    quiz1 = input("Which city were you born in? ")
    quiz2 = input("What is your nickname? ")
    quiz3 = input("What is your pet's name? ")
    if user_data[quiz1] == quiz1 and user_data['quiz1'] == quiz2 and user_data['quiz3'] == quiz3:
        reset_password(user_logs, username, user_data)
    else:
        print("*****************************************")
        print("Security question don't match. Password cannot reset!")


def main():
    user_logs = load_user_info()
    while True:
        print("*****************************")
        print("\n Choose an option\n *********************")
        print("Create an account")
        print("Login")
        print("Request password reset")
        print("Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            create_account(user_logs)
        elif choice == "2":
            login(user_logs)
        elif choice == "3":
            request_password_reset(user_logs)
        elif choice == "4":
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()