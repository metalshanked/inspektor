import os
import subprocess
import sys
from typing import List, Optional

def build_executable() -> None:
    """
    Build an executable for inspektor.py using PyInstaller.

    This function:
    1. Checks if PyInstaller is installed and installs it if needed
    2. Builds a standalone executable with appropriate options
    3. Verifies the build was successful

    Returns:
        None
    """
    print("Building executable for inspektor.py...")

    # Ensure PyInstaller is installed
    try:
        import PyInstaller
        print("PyInstaller is already installed.")
    except ImportError:
        print("PyInstaller not found. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

    # Build the executable with PyInstaller
    # We keep the --windowed flag as required, but we'll modify the application
    # to ensure console output is visible when in CLI mode
    build_command: List[str] = [
        "pyinstaller", 
        "--onefile",   # Create a single file executable
        "--windowed",  # Hide console window for GUI mode
        "--name", "inspektor",  # Name of the executable
        "--icon", "inspektor.ico",  # Application icon
        "--hidden-import", "automonitor",  # Include automonitor module
        "inspektor.py"
    ]

    print(f"Running command: {' '.join(build_command)}")
    subprocess.check_call(build_command)

    # Check if build was successful by verifying the executable exists
    executable_path: str = os.path.join("dist", "inspektor.exe")
    if os.path.exists(executable_path):
        print("\nBuild successful!")
        print(f"Executable created at: {os.path.abspath(executable_path)}")
    else:
        print("\nBuild failed. Executable not found.")

if __name__ == "__main__":
    build_executable()
