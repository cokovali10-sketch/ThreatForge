from setuptools import setup, find_packages

setup(
    name="threatforge",
    version="1.0.0",
    description="Open-source SOC (Security Operations Center) platform",
    author="Satuarb",
    author_email="satuarb@example.com",
    url="https://github.com/cokovali10-sketch/ThreatForge",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "threatforge": ["templates/*.html", "static/*.css", "static/*.js"],
    },
    install_requires=[
        "aiohttp>=3.9.0",
        "aiosqlite>=0.19.0",
        "scapy>=2.5.0",
    ],
    entry_points={
        "console_scripts": [
            "threatforge=threatforge.__main__:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
    ],
    python_requires=">=3.10",
)
