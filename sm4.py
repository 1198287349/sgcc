from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
# Press the green button in the gutter to run the script.
import base64

if __name__ == '__main__':
    key = b'联系QQ1198287349'
    iv = b'联系QQ1198287349'
    value = b'j09XOZYdG2UOeivVZ4ThwSE3v45Jid/6ShlLxSktc0bPOk+GPxPy8ZnFiPhzIYhG8N7yDyF8fne4mIEYuXQhDRg+0kqq3hBRF8IoBh6K1lr2altCECpML75J0c+mGqqqalBRGCF+lA53rcHHh4B4ow=='
    encrypt_value =base64.b64decode(value)
    crypt_sm4 = CryptSM4()
    crypt_sm4.set_key(key, SM4_DECRYPT)
    decrypt_value = crypt_sm4.crypt_cbc(iv=iv,input_data=encrypt_value)  # bytes类型
    print(repr(decrypt_value.decode(encoding='GBK')))
