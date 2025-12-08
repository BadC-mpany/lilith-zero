# scripts/setup/generate_keys.py
import os
import sys
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

def generate_keys(output_dir):
    print(f"Generating Ed25519 key pair in: {output_dir}")
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate private key
    private_key = ed25519.Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Generate public key
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Write files
    priv_path = os.path.join(output_dir, 'interceptor_private.pem')
    pub_path = os.path.join(output_dir, 'mcp_public.pem')

    with open(priv_path, 'wb') as f:
        f.write(private_bytes)
    
    with open(pub_path, 'wb') as f:
        f.write(public_bytes)

    print(f"  [OK] Private key: {priv_path}")
    print(f"  [OK] Public key:  {pub_path}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python generate_keys.py <output_directory>")
        sys.exit(1)
    
    generate_keys(sys.argv[1])
