#!/usr/bin/env python3
from setuptools import setup, find_packages

setup(
    name="rakshakai",
    version="3.0.0",
    description="RakshakAI v3 — Multi-model security CLI",
    packages=find_packages(include=["rakshakai*", "v2*"]),
    python_requires=">=3.9",
    install_requires=[
        "openai>=1.0.0",
        "rich>=13.0.0",
        "pygments>=2.0.0",
        "watchdog>=4.0.0",
        "GitPython>=3.1.0",
        "httpx>=0.25.0",
        "requests>=2.31.0",
    ],
    entry_points={
        "console_scripts": [
            "rakshak=rakshak_cli:main",
            "rakshakai=v2.cli.runner:main",
            "rkscan-ci=v2.cli.ci:main",
            "rkscan-mcp=v2.cli.mcp_server:main",
        ],
    },
)
