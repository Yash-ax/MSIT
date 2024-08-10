import re

def assess_password_strength(password):
    # Initialize strength score
    score = 0
    feedback = []

    # Criteria 1: Length
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Password should be at least 8 characters long.")

    # Criteria 2: Uppercase and Lowercase Letters
    if re.search("[A-Z]", password) and re.search("[a-z]", password):
        score += 1
    else:
        feedback.append("Password should contain both uppercase and lowercase letters.")

    # Criteria 3: Numbers
    if re.search("[0-9]", password):
        score += 1
    else:
        feedback.append("Password should contain at least one number.")

    # Criteria 4: Special Characters
    if re.search("[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    else:
        feedback.append("Password should contain at least one special character.")

    # Feedback based on score
    if score == 4:
        strength = "Strong"
    elif score == 3:
        strength = "Moderate"
    else:
        strength = "Weak"

    return strength, feedback

def main():
    print("Password Strength Checker")
    password = input("Enter your password: ")

    strength, feedback = assess_password_strength(password)
    
    print(f"Password Strength: {strength}")
    
    if feedback:
        print("Suggestions to improve your password:")
        for suggestion in feedback:
            print(f"- {suggestion}")

if __name__ == "__main__":
    main()
