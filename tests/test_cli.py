import os
import subprocess
import tempfile
import shutil
import time

def test_move_files_path():
    """Test the --move_files_path option in CLI mode."""
    # Create temporary directories
    scan_dir = tempfile.mkdtemp()
    move_dir = tempfile.mkdtemp()
    
    try:
        # Create a test file in the scan directory
        test_file_path = os.path.join(scan_dir, "test.txt")
        with open(test_file_path, "w") as f:
            f.write("This is a test file with the word encrypted in it.")
        
        print(f"Created test file: {test_file_path}")
        print(f"Scan directory: {scan_dir}")
        print(f"Move directory: {move_dir}")
        
        # Run the CLI command with --move_files_path
        cmd = [
            "python", "inspektor.py",
            "--mode", "auto",
            "--scan_dir", scan_dir,
            "--text_signatures", "encrypted",
            "--move_files_path", move_dir
        ]
        
        print(f"Running command: {' '.join(cmd)}")
        
        # Start the process
        process = subprocess.Popen(cmd)
        
        # Wait a bit for the file to be processed
        time.sleep(5)
        
        # Terminate the process
        process.terminate()
        
        # Check if the file was moved to the move directory
        moved_file_path = os.path.join(move_dir, "test.txt")
        if os.path.exists(moved_file_path):
            print(f"SUCCESS: File was moved to {moved_file_path}")
        else:
            print(f"FAILURE: File was not moved to {moved_file_path}")
            
            # Check if the file was moved to the default matches directory
            default_matches_dir = os.path.join(scan_dir, "matches")
            default_moved_file_path = os.path.join(default_matches_dir, "test.txt")
            if os.path.exists(default_moved_file_path):
                print(f"File was moved to the default matches directory: {default_moved_file_path}")
            elif os.path.exists(test_file_path):
                print(f"File is still in the original location: {test_file_path}")
            else:
                print(f"File is missing from both locations")
    
    finally:
        # Clean up
        shutil.rmtree(scan_dir, ignore_errors=True)
        shutil.rmtree(move_dir, ignore_errors=True)
        print("Cleaned up temporary directories")

if __name__ == "__main__":
    test_move_files_path()