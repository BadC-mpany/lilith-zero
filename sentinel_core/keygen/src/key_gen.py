from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def generate_keys():
    """
    Generates an Ed25519 Keypair.
    Ed25519 is chosen for high performance, small signature size,
    and resistance to side-channel attacks.
    """
    # Determine project root: go up from keygen/src to project root
    script_dir = Path(__file__).parent.absolute()  # keygen/src
    project_root = script_dir.parent.parent.parent  # sentinel_core/keygen/src -> sentinel_core/keygen -> sentinel_core -> project root

    # Ensure secrets directory exists
    secrets_dir = project_root / "sentinel_core" / "secrets"
    secrets_dir.mkdir(parents=True, exist_ok=True)

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
        encoding=serialization.Encoding.PEM,  # PEM - standard format for encoding public keys
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    private_key_path = secrets_dir / "interceptor_private.pem"
    public_key_path = secrets_dir / "mcp_public.pem"

    with open(private_key_path, "wb") as f:
        f.write(priv_pem)

    with open(public_key_path, "wb") as f:
        f.write(pub_pem)

    print(f"Keys generated: '{private_key_path}' and '{public_key_path}'")


if __name__ == "__main__":
    generate_keys()
