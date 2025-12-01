from setuptools import setup, find_packages

setup(
    name="sentinel-agent",
    version="0.1.0",
    packages=["sentinel_agent"],
    package_dir={"sentinel_agent": "src"},
    install_requires=[
        "sentinel-sdk",  # Install from local path
        "langchain>=0.1.0",
        "langchain-openai>=0.0.5",
        "langchain-core>=0.1.0",
        "rich>=13.0.0",
        "pyyaml>=6.0",
        "python-dotenv>=1.0.0",
    ],
    python_requires=">=3.10",
)
