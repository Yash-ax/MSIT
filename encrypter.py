def encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shift_amount = 65 if char.isupper() else 97
            encrypted_text += chr((ord(char) - shift_amount + shift) % 26 + shift_amount)
        else:
            encrypted_text += char
    return encrypted_text

def decrypt(text, shift):
    decrypted_text = ""
    for char in text:
        if char.isalpha():
            shift_amount = 65 if char.isupper() else 97
            decrypted_text += chr((ord(char) - shift_amount - shift) % 26 + shift_amount)
        else:
            decrypted_text += char
    return decrypted_text

def main():
    print("Caesar Cipher Encryption and Decryption")
    choice = input("Type 'E' to Encrypt or 'D' to Decrypt: ").upper()

    if choice not in ['E', 'D']:
        print("Invalid choice! Please choose 'E' or 'D'.")
        return

    message = input("Enter your message: ")
    try:
        shift = int(input("Enter the shift value: "))
    except ValueError:
        print("Invalid shift value! Please enter a number.")
        return

    if choice == 'E':
        result = encrypt(message, shift)
        print(f"Encrypted Message: {result}")
    elif choice == 'D':
        result = decrypt(message, shift)
        print(f"Decrypted Message: {result}")

if __name__ == "__main__":
    main()
