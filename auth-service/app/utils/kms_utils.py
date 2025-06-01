from google.cloud import kms_v1
from fastapi import HTTPException

async def encrypt_data_with_kms(
    kms_client: kms_v1.KeyManagementServiceClient,
    kms_key_id: str,
    plaintext: str
) -> bytes:
    """Encrypts plaintext using the specified KMS key."""
    if not kms_key_id:
        raise HTTPException(status_code=500, detail="KMS key ID not configured for encryption.")
    try:
        encrypt_response = kms_client.encrypt(
            request={"name": kms_key_id, "plaintext": plaintext.encode("utf-8")}
        )
        return encrypt_response.ciphertext
    except Exception as e:
        print(f"KMS encryption failed: {e}")
        raise HTTPException(status_code=500, detail="Data encryption failed.")

async def decrypt_data_with_kms(
    kms_client: kms_v1.KeyManagementServiceClient,
    kms_key_id: str,
    ciphertext: bytes
) -> str:
    """Decrypts ciphertext using the specified KMS key."""
    if not kms_key_id:
        raise HTTPException(status_code=500, detail="KMS key ID not configured for decryption.")
    try:
        decrypt_response = kms_client.decrypt(
            request={"name": kms_key_id, "ciphertext": ciphertext}
        )
        return decrypt_response.plaintext.decode("utf-8")
    except Exception as e:
        print(f"KMS decryption failed: {e}")
        raise HTTPException(status_code=500, detail="Data decryption failed.")
