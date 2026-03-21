from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="shieldmyrepo",
    version="0.1.0",
    author="Dhanush Nehru",
    author_email="dhanush@shieldmyrepo.dev",
    description="Scan any repo for security nightmares in 30 seconds",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/DhanushNehru/ShieldMyRepo",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
    python_requires=">=3.8",
    install_requires=[
        "click>=8.0",
        "rich>=13.0",
        "pyyaml>=6.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
            "flake8>=6.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "shieldmyrepo=shieldmyrepo.cli:main",
        ],
    },
)
