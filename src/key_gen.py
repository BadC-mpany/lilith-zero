import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def generate_keys():
    """
    Generates an Ed25519 Keypair.
    Ed25519 is chosen for high performance, small signature size,
    and resistance to side-channel attacks.
    """
    # Ensure secrets directory exists
    secrets_dir = "secrets"
    os.makedirs(secrets_dir, exist_ok=True)
    
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Serialize Private Key (For Interceptor)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize Public Key (For MCP Server)
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    private_key_path = os.path.join(secrets_dir, "interceptor_private.pem")
    public_key_path = os.path.join(secrets_dir, "mcp_public.pem")
    
    with open(private_key_path, "wb") as f:
        f.write(priv_pem)

    with open(public_key_path, "wb") as f:
        f.write(pub_pem)

    print(f"Keys generated: '{private_key_path}' and '{public_key_path}'")


if __name__ == "__main__":
    generate_keys()
