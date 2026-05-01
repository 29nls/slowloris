from setuptools import setup

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="slowloris",
    py_modules=["slowloris"],
    entry_points={"console_scripts": ["slowloris=slowloris:main"]},
    version="0.3.0",
    description="Low bandwidth DoS tool - Slowloris rewrite in Python",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="MACENG",
    author_email="niellsamosir@gmail.com",
    url="https://github.com/29nls/slowloris",
    keywords=["dos", "http", "slowloris", "security", "testing"],
    license="MIT",
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
    ],
    project_urls={
        "Bug Reports": "https://github.com/299nls/slowloris/issues",
        "Source": "https://github.com/29nls/slowloris",
    },
    extras_require={
        "proxy": ["python-socks>=1.2.0"],
    },
)
