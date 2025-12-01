from setuptools import setup, find_packages

setup(
    name="sentinel-sdk",
    version="0.1.0",
    packages=["sentinel_sdk"],
    package_dir={"sentinel_sdk": "src"},
    install_requires=[
        "httpx>=0.24.0",
        "langchain-core>=0.1.0",
        "pydantic>=1.10.0",
    ],
    python_requires=">=3.10",
)
