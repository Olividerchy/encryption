from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

def encrypt_message(message, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv, ct

def decrypt_message(iv, ct, key):
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ct)
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

def main():
    print("Добро пожаловать в программу шифрования и расшифровки сообщений!")
    while True:
        operation = input("Введите 'шифровать' для шифрования или 'расшифровать' для расшифровки (или 'выход' для завершения): ").lower()
        
        if operation == 'выход':
            print("До свидания!")
            break
        elif operation == 'шифровать':
            message = input("Введите сообщение для шифрования: ")
            key = input("Введите ключ (16, 24 или 32 байта): ")
            if len(key) not in [16, 24, 32]:
                print("Неверная длина ключа. Ключ должен быть длиной 16, 24 или 32 байта.")
                continue
            iv, encrypted_message = encrypt_message(message, key)
            print(f"Зашифрованное сообщение: {encrypted_message}")
            print(f"Инициализационный вектор (IV): {iv}")
        elif operation == 'расшифровать':
            iv = input("Введите инициализационный вектор (IV): ")
            encrypted_message = input("Введите зашифрованное сообщение: ")
            key = input("Введите ключ (16, 24 или 32 байта): ")
            if len(key) not in [16, 24, 32]:
                print("Неверная длина ключа. Ключ должен быть длиной 16, 24 или 32 байта.")
                continue
            try:
                decrypted_message = decrypt_message(iv, encrypted_message, key)
                print(f"Расшифрованное сообщение: {decrypted_message}")
            except Exception as e:
                print("Ошибка при расшифровке сообщения:", e)
        else:
            print("Неверная команда. Пожалуйста, попробуйте снова.")
    
    input("Нажмите Enter для выхода...")

if __name__ == '__main__':
    main()


