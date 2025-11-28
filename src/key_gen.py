from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def generate_keys():
    """
    Generates an Ed25519 Keypair.
    Ed25519 is chosen for high performance, small signature size,
    and resistance to side-channel attacks.
    """
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

    with open("interceptor_private.pem", "wb") as f:
        f.write(priv_pem)

    with open("mcp_public.pem", "wb") as f:
        f.write(pub_pem)

    print("Keys generated: 'interceptor_private.pem' and 'mcp_public.pem'")


if __name__ == "__main__":
    generate_keys()
