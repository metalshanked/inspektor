import time
import PySimpleGUI as sg
import os
import sys
import multiprocessing
import concurrent.futures
import binascii
import re
import csv
import shutil
import json
import logging
import argparse
import webbrowser
import operator
from logging.handlers import RotatingFileHandler
from typing import List, Dict, Tuple, Set, Optional, Union
from automonitor import AutoMonitor
import psgtray

# Constants
RESULT_TABLE_HEADERS = ["Filename", "Has Hex Signature", "Text Match", "Hex Matches", "Text Matches"]

# Global variables for table sorting
LAST_SORTED_COLUMN = None
SORT_REVERSE = False

# For console handling in CLI mode when built with --windowed
if sys.platform == 'win32':
    try:
        import ctypes
        kernel32 = ctypes.WinDLL('kernel32')
        AttachConsole = kernel32.AttachConsole
        FreeConsole = kernel32.FreeConsole
        AllocConsole = kernel32.AllocConsole
        ATTACH_PARENT_PROCESS = -1
    except ImportError:
        # If import fails, we'll fall back to normal behavior
        AttachConsole = None

# Custom application icon (magnifying glass) - base64 encoded
#INSPEKTOR_ICON_BASE64 = 'iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAABhklEQVR4nOWaW24DMQhFL2c73WC7gm4wXY+rfkQajZJ52oDL+YgSKTFwDY7Hxlpruot9/ewO0r4/TAmxqwIcCXoGMeysAHcCzyiEHRVgK/Ajgdz9fagA9sL5O073Hm+YADbY0QxCEOncq/F6rjGXM8BWTnjMSoTNzQzwdiRqDWBrJrydWtrzKgUi628PD3/IlpJh/wIWmPqRpYCKQ7bZ984CVBxUHNPnI136Lxldnqg4qDioOKg4qDioOKg4qDhEHEIcxeMZBRUHFYe/l4xl4PWIjorD802mLPA8oOGIE55422X5Idt5gIc/bBl1v6cLOJtk7wteIqztuNltb67Hva6u9wINWwSbw9X1kfFGZ4Jl6hCJaKOxbD1C3iJYxi4xTxEsa5+glwiWuVPUQwTrIcBIRouAkrMVZI/1CE3ASBHQJIwSAU3ECBHQZPQWAU1ITxHQpPQSAU3MOxHO7A/Q5KyDPbs5Qv+AZ9CXttst+VZ4NKg4qDioOKg4qDioOKg4qDhEOxDNL19QJmae7GzJAAAAAElFTkSuQmCC'
APP_VERSION = 'v0.1 [ALPHA]'

def clean_text_for_search(byte_data: bytes) -> str:
    """Clean binary data to get searchable text by removing null bytes and non-printable chars."""
    # Remove null bytes
    cleaned = byte_data.replace(b'\x00', b'')

    # Replace non-printable chars with space
    result = b''
    for b in cleaned:
        if 32 <= b <= 126 or b in (9, 10, 13):  # printable ASCII or tab/newline/carriage return
            result += bytes([b])
        else:
            result += b' '

    # Decode to string, replacing any characters that can't be decoded
    return result.decode('utf-8', errors='replace')

def hex_string_to_bytes(hex_string: str) -> bytes:
    """Convert a hex string like '50 4B 03 04' to bytes."""
    # Remove spaces and convert to bytes
    clean_hex = hex_string.replace(' ', '')
    # Pad with a leading zero if the length is odd
    if len(clean_hex) % 2 != 0:
        clean_hex = '0' + clean_hex
    return binascii.unhexlify(clean_hex)

def check_file_for_hex_signatures(file_path: str, hex_signatures: List[str], max_load_bytes: int = 1024) -> List[str]:
    """
    Check if a file contains any of the specified hex signatures.

    Args:
        file_path: Path to the file to check
        hex_signatures: List of hex signatures to check for (e.g., ["50 4B 03 04"])
        max_load_bytes: Maximum number of bytes to load from the file

    Returns:
        List of matched signatures
    """
    matched_signatures = []

    # Convert hex signatures to bytes for comparison
    byte_signatures = [hex_string_to_bytes(sig) for sig in hex_signatures]
    logging.debug(f"Hex signatures converted to bytes: {byte_signatures}")

    max_retries = 5
    retry_count = 0

    while retry_count < max_retries:
        try:
            with open(file_path, 'rb') as f:
                # Read the specified number of bytes (or 50 bytes if max_load_bytes is less than 50)
                header = f.read(max_load_bytes)

                for i, sig_bytes in enumerate(byte_signatures):
                    if sig_bytes in header:
                        matched_signatures.append(hex_signatures[i])
            # If successful, break out of the retry loop
            break
        except PermissionError as e:
            retry_count += 1
            logging.warning(f"Permission denied when checking file {file_path}: {e} (Attempt {retry_count} of {max_retries})")
            if retry_count >= max_retries:
                # Re-raise to be caught by the caller if all retries failed
                logging.error(f"All {max_retries} attempts failed for {file_path}")
                raise
            # Pause before retrying
            time.sleep(1)
        except Exception as e:
            logging.error(f"Error checking file {file_path}: {e}")
            break

    return matched_signatures

def check_file_for_text_signatures(file_path: str, text_signatures: List[str], match_all: bool, max_load_bytes: int = 1024) -> Tuple[List[str], bool]:
    """
    Check if a file contains specified text signatures.

    Args:
        file_path: Path to the file to check
        text_signatures: List of text signatures to check for
        match_all: If True, all signatures must be found; otherwise, any match is sufficient
        max_load_bytes: Maximum number of bytes to load from the file

    Returns:
        Tuple of (matched signatures, overall match result)
    """
    matched_signatures = []
    remaining_signatures = set(text_signatures)
    encodings = ['cp1252', 'utf-8', 'latin-1', 'ascii']

    max_retries = 5
    retry_count = 0

    while retry_count < max_retries:
        try:
            # Open the file in binary read mode
            with open(file_path, 'rb') as f:
                # Read only the specified number of bytes
                byte_data = f.read(max_load_bytes)

                if not byte_data:  # Empty file
                    return [], False

                # Try to decode the byte data using different encodings
                searchable_text = None
                for encoding in encodings:
                    try:
                        # Decode the byte data using the current encoding
                        decoded_string = byte_data.decode(encoding)
                        # Remove null characters from the decoded string
                        decoded_string = decoded_string.replace('\x00', '')
                        searchable_text = decoded_string
                        break
                    except UnicodeDecodeError:
                        # If decoding fails, try the next encoding in the list
                        continue

                # If all encodings fail, use the clean_text_for_search function as fallback
                if searchable_text is None:
                    searchable_text = clean_text_for_search(byte_data)

                # Check for each text signature
                for signature in list(remaining_signatures):
                    if signature.lower() in searchable_text.lower():
                        matched_signatures.append(signature)
                        remaining_signatures.remove(signature)

            # If successful, break out of the retry loop
            break
        except PermissionError as e:
            retry_count += 1
            logging.warning(f"Permission denied when checking file {file_path}: {e} (Attempt {retry_count} of {max_retries})")
            if retry_count >= max_retries:
                # Re-raise to be caught by the caller if all retries failed
                logging.error(f"All {max_retries} attempts failed for {file_path}")
                raise
            # Pause before retrying
            time.sleep(1)
        except Exception as e:
            logging.error(f"Error checking file {file_path}: {e}")
            break

    # Determine if the match criteria is satisfied
    if match_all:
        match_result = len(matched_signatures) == len(text_signatures)
    else:
        match_result = len(matched_signatures) > 0

    return matched_signatures, match_result

def process_file(args: Tuple[str, List[str], List[str], bool, int]) -> Dict:
    """
    Process a single file to check for hex and text signatures.
    This function is designed to be used with ThreadPoolExecutor.

    Args:
        args: Tuple containing (file_path, hex_signatures, text_signatures, match_all_text, max_load_bytes)

    Returns:
        Dictionary with results
    """
    file_path, hex_signatures, text_signatures, match_all_text, max_load_bytes = args

    result = {
        'file_path': file_path,
        'file_name': os.path.basename(file_path),
        'hex_matches': [],
        'text_matches': [],
        'has_hex_signature': False,
        'text_match_result': False
    }

    # Check for hex signatures if any are provided
    if hex_signatures:
        result['hex_matches'] = check_file_for_hex_signatures(file_path, hex_signatures, max_load_bytes)
        result['has_hex_signature'] = len(result['hex_matches']) > 0

    # Check for text signatures if any are provided
    if text_signatures:
        result['text_matches'], result['text_match_result'] = check_file_for_text_signatures(
            file_path, text_signatures, match_all_text, max_load_bytes
        )

    return result

def get_all_files_in_directory(directory_path: str, recursive: bool = True, file_extensions: str = "", exclude_dirs: List[str] = None) -> List[str]:
    """
    Get all file paths in a directory, optionally filtered by file extensions.

    Args:
        directory_path: Path to the directory
        recursive: Whether to include files in subdirectories
        file_extensions: Comma-separated list of file extensions to include (e.g., ".txt,.pdf,.docx")
                         If empty, "*.*", or ".*", all files are included
        exclude_dirs: [DEPRECATED] This parameter is no longer used

    Returns:
        List of file paths
    """
    file_paths = []

    # Process file extensions
    extensions = []
    if file_extensions and file_extensions.strip() not in ["*.*", ".*"]:
        extensions = [ext.strip().lower() for ext in file_extensions.split(",") if ext.strip()]
        # Add leading dot if missing
        extensions = ["." + ext if not ext.startswith(".") else ext for ext in extensions]

    # Function to check if a file should be included based on its extension
    def should_include_file(filename):
        if not extensions:  # If no extensions specified, include all files
            return True
        file_ext = os.path.splitext(filename)[1].lower()
        return file_ext in extensions

    if recursive:
        # Walk through all subdirectories
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                if should_include_file(file):
                    file_paths.append(os.path.join(root, file))
    else:
        # Only get files in the top directory
        for item in os.listdir(directory_path):
            item_path = os.path.join(directory_path, item)
            if os.path.isfile(item_path) and should_include_file(item):
                file_paths.append(item_path)

    return file_paths

def process_files_with_progress(file_paths: List[str], hex_signatures: List[str],
                 text_signatures: List[str], match_all_text: bool,
                 max_load_bytes: int = 1024, progress_callback=None) -> List[Dict]:
    """
    Process multiple files in parallel using ThreadPoolExecutor with progress updates.

    Args:
        file_paths: List of file paths to process
        hex_signatures: List of hex signatures to check for
        text_signatures: List of text signatures to check for
        match_all_text: Whether all text signatures must match
        max_load_bytes: Maximum number of bytes to load from each file
        progress_callback: Optional callback function to report progress

    Returns:
        List of dictionaries with results for each file
    """
    # If no files to process, return empty list
    if not file_paths:
        return []

    # Determine optimal number of workers based on number of files and CPU cores
    cpu_count = multiprocessing.cpu_count()
    total_files = len(file_paths)

    # Use a reasonable number of workers
    max_workers = min(32, cpu_count * 2)  # Limit max workers to avoid too many threads

    logging.info(f"Processing {total_files} files using ThreadPoolExecutor with {max_workers} workers")

    # Process files in smaller batches to provide progress updates
    results = []
    batch_size = max(10, max_workers * 5)  # Process in reasonable batches

    for i in range(0, total_files, batch_size):
        # Get the current batch of files
        batch_files = file_paths[i:i+batch_size]
        batch_args = [(file_path, hex_signatures, text_signatures, match_all_text, max_load_bytes)
                     for file_path in batch_files]

        # Process this batch using ThreadPoolExecutor
        batch_results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks and collect futures
            future_to_arg = {executor.submit(process_file, arg): arg for arg in batch_args}

            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_arg):
                batch_results.append(future.result())

        # Add results to the main list
        results.extend(batch_results)

        # Report progress if callback is provided
        if progress_callback:
            progress_percent = min(100, int((i + len(batch_files)) / total_files * 100))
            progress_callback(progress_percent, f"Processed {i + len(batch_files)} of {total_files} files")

    return results

# Keep the original function for backward compatibility
def process_files(file_paths: List[str], hex_signatures: List[str],
                 text_signatures: List[str], match_all_text: bool,
                 max_load_bytes: int = 1024) -> List[Dict]:
    """
    Process multiple files in parallel using ThreadPoolExecutor.

    Args:
        file_paths: List of file paths to process
        hex_signatures: List of hex signatures to check for
        text_signatures: List of text signatures to check for
        match_all_text: Whether all text signatures must match
        max_load_bytes: Maximum number of bytes to load from each file

    Returns:
        List of dictionaries with results for each file
    """
    return process_files_with_progress(file_paths, hex_signatures, text_signatures, match_all_text, max_load_bytes)

def get_state_file_path():
    """Get the path to the state file."""
    # Use the user's home directory or the application directory
    app_dir = os.path.join(os.path.expanduser("~"), ".inspektor")

    # Create the directory if it doesn't exist
    if not os.path.exists(app_dir):
        try:
            os.makedirs(app_dir)
        except Exception as e:
            logging.error(f"Error creating app directory: {e}")
            # Fallback to current directory if home directory is not accessible
            app_dir = get_application_path()
            if not os.path.exists(app_dir):
                os.makedirs(app_dir)

    return os.path.join(app_dir, "state.json")

def get_application_path():
    """Get the path of the application directory, works for both script and executable."""
    if getattr(sys, 'frozen', False):
        # If the application is run as a bundle (executable)
        application_path = os.path.dirname(sys.executable)
    else:
        # If the application is run as a script
        application_path = os.path.dirname(os.path.abspath(__file__))

    return application_path

def setup_logging(log_dir=None):
    """Set up logging with rotation capabilities.

    Args:
        log_dir (str, optional): Directory to store log files. Defaults to 'logs' subfolder in application directory.

    Returns:
        str: Path to the log directory
    """
    try:
        # If log_dir is not provided, use the 'logs' subfolder in the application directory
        if not log_dir:
            app_path = get_application_path()
            log_dir = os.path.join(app_path, "logs")

        # Ensure the log directory exists
        os.makedirs(log_dir, exist_ok=True)

        # Set up the log file path
        log_file = os.path.join(log_dir, "inspektor.log")

        # Configure the root logger
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)

        # Remove any existing handlers to avoid duplicates
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)

        # Create a rotating file handler (max 5 files, 100MB each)
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=100*1024*1024,  # 100MB
            backupCount=5
        )

        # Set the format for log messages
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)

        # Add the handler to the logger
        logger.addHandler(file_handler)

        # Add a console handler for debugging purposes
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        # Log the initialization
        logging.info("Logging initialized. Log file: %s", log_file)

        return log_dir
    except Exception as e:
        # If logging setup fails, set up a basic console logger
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)

        # Remove any existing handlers
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)

        # Add a console handler
        console_handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        # Log the error
        logging.error(f"Error setting up logging: {e}")
        logging.info(f"Falling back to console logging only")

        # Still return the log_dir even if we couldn't create the file handler
        return log_dir


def save_state(values, selected_files, selected_directory, log_dir=None):
    """Save the application state to a file."""
    # Check if values is None before trying to access its elements
    if values is None:
        logging.warning("Values is None, cannot save state")
        return

    state = {
        "hex_signatures": values["-HEX_SIGNATURES-"],
        "text_signatures": values["-TEXT_SIGNATURES-"],
        "match_all": values["-MATCH_ALL-"],
        "recursive": values["-RECURSIVE-"],
        "max_load_bytes": values["-MAX_LOAD_BYTES-"],
        "file_extensions": values["-FILE_EXTENSIONS-"],
        "selected_files": selected_files,
        "selected_directory": selected_directory,
        "log_dir": log_dir
    }

    try:
        with open(get_state_file_path(), 'w') as f:
            json.dump(state, f)
        logging.info("Application state saved successfully")
    except Exception as e:
        logging.error(f"Error saving state: {e}")

def load_state():
    """Load the application state from a file."""
    state_file = get_state_file_path()

    if not os.path.exists(state_file):
        return None

    try:
        with open(state_file, 'r') as f:
            state = json.load(f)
            logging.info("Application state loaded successfully")
            return state
    except Exception as e:
        logging.error(f"Error loading state: {e}")
        return None

def create_layout():
    """Create the layout for the PySimpleGUI window."""
    # Define the header with title and logo
    header = [
        [
            sg.Image(data=sg.EMOJI_BASE64_LAPTOP, size=(25, 25), pad=((10, 5), (10, 10))),  # Custom magnifying glass icon
            sg.Text("Inspektor", font=("Helvetica", 24, "bold"), pad=((0, 0), (10, 10))),
            sg.Text("File Analysis Tool", font=("Helvetica", 16), pad=((15, 0), (15, 10)))
        ]
    ]

    # Define the sidebar
    sidebar = [
        [sg.Text("Mode", font=("Helvetica", 12))],
        [sg.Radio("Manual", "MODE", default=True, key="-MANUAL_MODE-", enable_events=True),
         sg.Radio("Auto", "MODE", default=False, key="-AUTO_MODE-", enable_events=True)],
        [sg.HorizontalSeparator()],
        [sg.Text("File Extensions", font=("Helvetica", 12))],
        [sg.Multiline(default_text=".pptx, .docx, .xlsx", size=(30, 3), key="-FILE_EXTENSIONS-", tooltip="Comma-separated list of file extensions to scan (e.g., .txt,.pdf,.docx). Leave empty to scan all files.")],
        [sg.Text("Hex Signatures", font=("Helvetica", 12)), sg.Text("[info]", key="-HEX_INFO_LINK-", text_color="blue", enable_events=True, tooltip="https://en.wikipedia.org/wiki/List_of_file_signatures")],
        [sg.Multiline(default_text="50 4B 03 04\n50 4B 05 06\n50 4B 07 08", size=(30, 3), key="-HEX_SIGNATURES-")],
        [sg.Text("Text Signatures", font=("Helvetica", 12))],
        [sg.Multiline(default_text="voltage\nencrypt", size=(30, 3), key="-TEXT_SIGNATURES-")],
        [sg.Checkbox("Match All Text Signatures", default=False, key="-MATCH_ALL-")],
        [sg.Text("Maximum Load Bytes", font=("Helvetica", 12))],
        [sg.Input("1024", size=(10, 1), key="-MAX_LOAD_BYTES-"), sg.Text("bytes")]
    ]

    # Define the main content area
    main_content = [
        [sg.Column([
            [sg.InputText(key="-FILE_PATH-", visible=False, enable_events=True),
             sg.FilesBrowse("Select Files", file_types=(("All Files", "*.*"),),
                            tooltip="Select one or more files to analyze"),
             sg.InputText(key="-DIR_PATH-", visible=False, enable_events=True),
             sg.FolderBrowse("Select Directory", tooltip="Select a directory to scan for files"),
             sg.Checkbox("Include Subdirectories", default=False, key="-RECURSIVE-"),
             sg.Button("Reset", key="-RESET-", tooltip="Clear all signatures and reset to defaults",
                       disabled_button_color=("gray", "lightgray")),
             sg.InputText(key="-LOG_DIR-", visible=False, enable_events=True),
             sg.FolderBrowse("Set Log Directory", key="-SET_LOG_DIR-", target="-LOG_DIR-",
                            tooltip="Set directory for log files"),
             sg.Button("Minimize to Tray", key="-MINIMIZE_TO_TRAY-", tooltip="Minimize application to system tray")]
        ], element_justification='right', expand_x=True)],
        [sg.ProgressBar(100, orientation='h', size=(50, 20), key='-PROGRESS-', visible=False)],
        [sg.Text("", key="-STATUS-")],
        [sg.Table(
            values=[],
            headings=RESULT_TABLE_HEADERS,
            auto_size_columns=False,
            col_widths=[30, 15, 15, 30, 30],
            justification="left",
            num_rows=10,
            key="-RESULTS_TABLE-",
            tooltip="Analysis Results",
            enable_click_events=True,
            vertical_scroll_only=False
        )],
        []
    ]

    # Define info banner
    info_banner = [
        [sg.Text("Please select file(s) or choose a directory", key="-INFO_BANNER-", font=("Helvetica", 10), text_color="blue", size=(80, 1))]
    ]

    # Combine header, info banner, sidebar and main content
    layout = [
        # Header row that spans the entire width
        [sg.Column(header, element_justification='left', expand_x=True)],
        # Separator below header
        [sg.HorizontalSeparator()],
        # Info banner row
        [sg.Column(info_banner, element_justification='left', expand_x=True, pad=((10, 0), (5, 5)))],
        # Separator below info banner
        [sg.HorizontalSeparator()],
        # Content row with sidebar and main area
        [
            sg.Column(sidebar, element_justification='left', vertical_alignment='top', pad=((0, 10), 0)),
            sg.VSeperator(),
            sg.Column(main_content, element_justification='center', vertical_alignment='top', expand_x=True, expand_y=True)
        ],
        # Footer with buttons aligned to the right
        [sg.Column([[
            sg.Button("Analyze", key="-ANALYZE-", tooltip="Start analyzing the selected files",
                   size=(20, 2), font=("Helvetica", 10), button_color=("white", "teal"), disabled_button_color=("gray", "lightgray")),
            sg.Button("Export to CSV", size=(20, 2),key="-EXPORT_CSV-", disabled=True, tooltip="Export results to a CSV file", disabled_button_color=("gray", "lightgray")),
            sg.Button("Organize Files", size=(20, 2),key="-ORGANIZE_FILES-", disabled=True, tooltip="Move matched files to a selected directory", disabled_button_color=("gray", "lightgray"))
        ]], element_justification='right', expand_x=True, pad=(0, 10))]
    ]

    return layout

def update_analyze_button_state(window, hex_signatures, text_signatures, selected_files, selected_directory, is_auto_mode=False):
    """Update the state of the Analyze button based on signatures and file selection."""
    # Check if any signatures are entered
    has_signatures = bool(hex_signatures.strip() or text_signatures.strip())

    # Check if any files or directory is selected
    has_files = bool(selected_files or selected_directory)

    # If in auto mode, always disable the analyze button
    if is_auto_mode:
        window["-ANALYZE-"].update(disabled=True)
    else:
        # Enable the button only if both conditions are met
        window["-ANALYZE-"].update(disabled=not (has_signatures and has_files))

    return has_signatures, has_files

def update_info_banner(window, selected_files, selected_directory, has_signatures, has_files, is_auto_mode=False):
    """Update the info banner with appropriate messages."""
    if is_auto_mode:
        if not selected_directory:
            window["-INFO_BANNER-"].update("Please choose a directory to monitor")
        elif not has_signatures:
            window["-INFO_BANNER-"].update("Please enter at least one hex or text signature")
        else:
            window["-INFO_BANNER-"].update(f"Auto monitoring directory: {selected_directory}")
    else:
        if not has_files:
            window["-INFO_BANNER-"].update("Please select file(s) or choose a directory")
        elif not has_signatures:
            window["-INFO_BANNER-"].update("Please enter at least one hex or text signature")
        elif selected_files:
            window["-INFO_BANNER-"].update(f"Loaded {len(selected_files)} file(s)")
        elif selected_directory:
            window["-INFO_BANNER-"].update(f"Loaded directory: {selected_directory}")

def update_ui_for_mode(window, is_auto_mode, selected_directory=None):
    """Update UI elements based on the selected mode."""
    if is_auto_mode:
        # Disable file selection
        window["Select Files"].update(disabled=True)

        # Disable analyze button
        window["-ANALYZE-"].update(disabled=True)

        # Disable export and organize buttons
        window["-EXPORT_CSV-"].update(disabled=True)
        window["-ORGANIZE_FILES-"].update(disabled=True)

        # Uncheck and disable recursive checkbox
        window["-RECURSIVE-"].update(value=False, disabled=True)

        # Enable directory selection
        window["Select Directory"].update(disabled=False)

        # Update status
        if selected_directory:
            window["-STATUS-"].update(f"Auto monitoring directory: {selected_directory}")
        else:
            window["-STATUS-"].update("Auto mode enabled. Please select a directory to monitor.")
    else:
        # Enable all controls
        window["Select Files"].update(disabled=False)
        window["Select Directory"].update(disabled=False)
        window["-RECURSIVE-"].update(disabled=False)

        # Analyze button state depends on other conditions, handled elsewhere

        # Update status
        window["-STATUS-"].update("Manual mode enabled.")

def process_file_auto(file_path: str, hex_signatures: List[str], text_signatures: List[str],
                match_all_text: bool, max_load_bytes: int, target_dir: str) -> bool:
    """
    Process a single file in auto mode and move it to the target directory if it matches.

    Args:
        file_path: Path to the file to process
        hex_signatures: List of hex signatures to check for
        text_signatures: List of text signatures to check for
        match_all_text: Whether all text signatures must match
        max_load_bytes: Maximum number of bytes to load from the file
        target_dir: Directory to move matched files to

    Returns:
        True if the file was processed and moved, False otherwise
    """
    try:
        # Process the file
        result = process_file((file_path, hex_signatures, text_signatures, match_all_text, max_load_bytes))

        # Check if the file matches any signatures
        if result["has_hex_signature"] or result["text_match_result"]:
            # Get the filename without path
            filename = os.path.basename(file_path)
            # Create the destination path
            dest_path = os.path.join(target_dir, filename)

            # Handle file name conflicts
            if os.path.exists(dest_path):
                base, ext = os.path.splitext(filename)
                counter = 1
                while os.path.exists(dest_path):
                    new_filename = f"{base}_{counter}{ext}"
                    dest_path = os.path.join(target_dir, new_filename)
                    counter += 1

            # Move the file
            shutil.move(file_path, dest_path)
            logging.info(f"Auto moved file: {file_path} to {dest_path}")
            return True
    except PermissionError as e:
        logging.error(f"Permission error processing file in auto mode: {e}")
        # Skip files with permission errors
        return False
    except Exception as e:
        logging.error(f"Error processing file in auto mode: {e}")

    return False

def scan_directory_and_process(directory_path: str, hex_signatures: List[str],
                          text_signatures: List[str], match_all_text: bool,
                          max_load_bytes: int, target_dir: str,
                          recursive: bool = False, file_extensions: str = "") -> int:
    """
    Scan a directory for existing files and process them.

    Args:
        directory_path: Path to the directory to scan
        hex_signatures: List of hex signatures to check for
        text_signatures: List of text signatures to check for
        match_all_text: Whether all text signatures must match
        max_load_bytes: Maximum number of bytes to load from the file
        target_dir: Directory to move matched files to
        recursive: Whether to scan subdirectories recursively
        file_extensions: Comma-separated list of file extensions to scan (e.g., ".txt,.pdf,.docx")
                         If empty, "*.*", or ".*", all files are included

    Returns:
        Number of files processed
    """
    # Get all files in the directory
    files = get_all_files_in_directory(directory_path, recursive, file_extensions)

    processed_count = 0

    # Process each file
    for file_path in files:
        try:
            if process_file_auto(file_path, hex_signatures, text_signatures, match_all_text, max_load_bytes, target_dir):
                processed_count += 1
        except Exception as e:
            logging.error(f"Error during initial scan: {e}")

    logging.info(f"Initial scan complete. Processed {processed_count} files.")
    return processed_count

def parse_cli_args() -> argparse.Namespace:
    """
    Parse command line arguments for CLI mode.

    Returns:
        Parsed command line arguments
    """
    parser = argparse.ArgumentParser(description='Inspektor - File Analysis Tool (CLI Mode)')
    parser.add_argument('--mode', choices=['auto'], default='auto', help='Operation mode (currently only auto is supported)')
    parser.add_argument('--scan_dir', required=True, help='Directory to scan and monitor')
    parser.add_argument('--file_extensions', default='',
                        help='Comma-separated list of file extensions to scan (e.g., .txt,.pdf,.docx). Leave empty, use "*.*", or ".*" to scan all files')
    parser.add_argument('--hex_signatures', default='', help='Comma-separated list of hex signatures')
    parser.add_argument('--text_signatures', default='', help='Comma-separated list of text signatures')
    parser.add_argument('--match_all', action='store_true', help='Whether all text signatures must match')
    parser.add_argument('--max_load_bytes', type=int, default=1024, help='Maximum number of bytes to load from each file')
    parser.add_argument('--move_files_path', help='Custom directory path where matched files will be moved (default: "matches" subfolder in scan directory)')
    parser.add_argument('--log_dir', help='Directory to store log files (default: application directory)')

    return parser.parse_args()

def sort_table(table, cols, reverse=False):
    """
    Sort a table by multiple columns.

    Args:
        table: A list of lists (or tuple of tuples) where each inner list represents a row
        cols: A list (or tuple) specifying the column numbers to sort by
              e.g. (1,0) would sort by column 1, then by column 0
        reverse: If True, sort in descending order, otherwise ascending

    Returns:
        The sorted table
    """
    for col in reversed(cols):
        try:
            table = sorted(table, key=operator.itemgetter(col), reverse=reverse)
        except Exception as e:
            logging.error(f"Error in sort_table: {e}")
    return table

def run_cli_mode() -> None:
    """
    Run the application in CLI mode.

    This function parses command line arguments and runs the application in CLI mode,
    setting up monitoring for a specified directory.
    """
    # Attach to console when running in CLI mode (for executables built with --windowed)
    if sys.platform == 'win32' and AttachConsole is not None and getattr(sys, 'frozen', False):
        try:
            # Try to attach to parent console
            if not AttachConsole(ATTACH_PARENT_PROCESS):
                # If no parent console, allocate a new one
                AllocConsole()

            # Redirect stdout and stderr to the console
            sys.stdout = open('CONOUT$', 'w')
            sys.stderr = open('CONOUT$', 'w')
        except Exception as e:
            # If console attachment fails, we'll continue without it
            pass

    # Parse command line arguments
    args = parse_cli_args()

    # Initialize logging
    log_dir = setup_logging(args.log_dir)

    logging.info(f"Log directory set to: {log_dir}")
    logging.info("Running Inspektor in CLI mode...")

    # Validate arguments
    if not os.path.isdir(args.scan_dir):
        logging.error(f"Directory '{args.scan_dir}' does not exist or is not a directory")
        return 1

    # Parse hex signatures
    hex_signatures = [sig.strip() for sig in args.hex_signatures.split(',') if sig.strip()]

    # Parse text signatures
    text_signatures = [sig.strip() for sig in args.text_signatures.split(',') if sig.strip()]

    # Check if we have signatures
    if not (hex_signatures or text_signatures):
        logging.error("No hex or text signatures provided")
        return 1

    logging.info(f"Scanning directory: {args.scan_dir}")
    logging.info(f"File extensions: {args.file_extensions if args.file_extensions else 'All files'}")
    logging.info(f"Hex signatures: {hex_signatures}")
    logging.info(f"Text signatures: {text_signatures}")
    logging.info(f"Match all text signatures: {args.match_all}")
    logging.info(f"Max load bytes: {args.max_load_bytes}")

    # Determine the matches directory path
    if args.move_files_path:
        matches_dir = args.move_files_path
        logging.info(f"Using custom matches directory: {matches_dir}")
    else:
        matches_dir = os.path.join(args.scan_dir, "matches")
        logging.info(f"Using default matches directory: {matches_dir}")

    # Create matches directory if it doesn't exist
    if not os.path.exists(matches_dir):
        try:
            os.makedirs(matches_dir)
            logging.info(f"Created matches directory: {matches_dir}")
        except Exception as e:
            logging.error(f"Error creating matches directory: {e}")
            return 1

    # Create auto monitor instance
    auto_monitor = AutoMonitor()

    # Define callback function for processing files
    def process_file_callback(file_path: str) -> None:
        """
        Process a file detected by the auto monitor.

        Args:
            file_path: Path to the file to process
        """
        # Skip files in the matches directory
        if os.path.dirname(file_path) == matches_dir:
            return

        # Process the file and move it if it matches
        if process_file_auto(file_path, hex_signatures, text_signatures, args.match_all, args.max_load_bytes, matches_dir):
            logging.info(f"Match found: {file_path}")

    # Start monitoring the directory
    if auto_monitor.start_monitoring(
        args.scan_dir,
        process_file_callback,
        hex_signatures,
        text_signatures,
        args.match_all,
        args.max_load_bytes,
        args.file_extensions
    ):
        logging.info(f"Auto monitoring started for directory: {args.scan_dir}")

        # Perform initial scan of existing files
        logging.info("Performing initial scan...")
        processed_count = scan_directory_and_process(
            args.scan_dir,
            hex_signatures,
            text_signatures,
            args.match_all,
            args.max_load_bytes,
            matches_dir,
            file_extensions=args.file_extensions
        )
        logging.info(f"Initial scan complete. Processed {processed_count} files.")

        # Keep the application running until interrupted
        try:
            logging.info("Press Ctrl+C to stop monitoring")
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logging.info("\nStopping monitoring...")
            auto_monitor.stop_monitoring()
            logging.info("Monitoring stopped")

        return 0
    else:
        logging.error("Failed to start auto monitoring")
        return 1

def main() -> int:
    """
    Main function to run the application.

    This function is the entry point of the application. It checks if command line arguments
    are provided and runs in CLI mode if they are, otherwise it runs in GUI mode.

    Returns:
        Exit code (0 for success, non-zero for error)
    """
    # Check for command line arguments for headless CLI mode
    if len(sys.argv) > 1:
        sys.exit(run_cli_mode())

    # GUI mode
    # Initialize logging with default directory
    log_dir = setup_logging()

    sg.theme("DefaultNoMoreNagging")  # Set the theme

    layout = create_layout()

    # Create the window
    window = sg.Window(f"Inspektor - File Analysis Tool - {APP_VERSION}", layout, resizable=True, size=(1000, 600), finalize=True, enable_close_attempted_event=True, icon=sg.EMOJI_BASE64_LAPTOP)

    # Define system tray menu
    menu_def = ['', ['Show Window', 'Hide Window', '---', 'Exit']]

    # Create system tray icon
    tray = psgtray.SystemTray(menu_def, single_click_events=False, window=window, tooltip="Inspektor", icon=sg.EMOJI_BASE64_LAPTOP)

    # Selected files and directories
    selected_files = []
    selected_directory = None

    # Store analysis results
    results = []

    # Create auto monitor instance
    auto_monitor = AutoMonitor()
    is_auto_mode = False

    # Initially disable the Analyze button
    window["-ANALYZE-"].update(disabled=True)

    # Load saved state if available
    saved_state = load_state()
    if saved_state:
        # Update GUI elements with saved values
        if "hex_signatures" in saved_state:
            window["-HEX_SIGNATURES-"].update(saved_state["hex_signatures"])
        if "text_signatures" in saved_state:
            window["-TEXT_SIGNATURES-"].update(saved_state["text_signatures"])
        if "match_all" in saved_state:
            window["-MATCH_ALL-"].update(saved_state["match_all"])
        if "recursive" in saved_state:
            window["-RECURSIVE-"].update(saved_state["recursive"])
        if "max_load_bytes" in saved_state:
            window["-MAX_LOAD_BYTES-"].update(saved_state["max_load_bytes"])
        if "file_extensions" in saved_state:
            window["-FILE_EXTENSIONS-"].update(saved_state["file_extensions"])
        if "selected_files" in saved_state and saved_state["selected_files"]:
            selected_files = saved_state["selected_files"]
        if "selected_directory" in saved_state and saved_state["selected_directory"]:
            selected_directory = saved_state["selected_directory"]
        if "log_dir" in saved_state and saved_state["log_dir"]:
            # Reinitialize logging with the saved log directory
            log_dir = setup_logging(saved_state["log_dir"])

    # Get initial signature values from the window
    hex_signatures = window["-HEX_SIGNATURES-"].get()
    text_signatures = window["-TEXT_SIGNATURES-"].get()

    # Update the Analyze button state and info banner based on loaded state
    has_signatures, has_files = update_analyze_button_state(
        window,
        hex_signatures,
        text_signatures,
        selected_files,
        selected_directory,
        is_auto_mode
    )
    update_info_banner(window, selected_files, selected_directory, has_signatures, has_files, is_auto_mode)

    # Event loop
    while True:
        event, values = window.read()

        # IMPORTANT: Handle system tray events
        if isinstance(event, (str, int)) and event == tray.key:
            event = values[event]  # Use the system tray's event as if it was from the window

        if isinstance(event, (str, int)) and event in (sg.WINDOW_CLOSED, 'Exit', sg.WIN_CLOSE_ATTEMPTED_EVENT):
            # Stop auto monitoring if active
            if is_auto_mode:
                auto_monitor.stop_monitoring()

            # Save state before closing
            save_state(values, selected_files, selected_directory, log_dir)

            # Close system tray
            tray.close()
            break

        if isinstance(event, (str, int)) and event in ('Show Window', sg.EVENT_SYSTEM_TRAY_ICON_DOUBLE_CLICKED):
            window.un_hide()
            window.bring_to_front()
        elif isinstance(event, str) and event in ('Hide Window'):
            window.hide()
            tray.show_icon()  # Make sure the icon is visible

        if isinstance(event, str) and event == "-MINIMIZE_TO_TRAY-":
            # Hide the window and ensure tray icon is visible
            window.hide()
            tray.show_icon()
            window["-STATUS-"].update("Application minimized to system tray")

        if isinstance(event, str) and event == "-HEX_INFO_LINK-":
            # Open the Wikipedia page for file signatures
            webbrowser.open("https://en.wikipedia.org/wiki/List_of_file_signatures")
            window["-STATUS-"].update("Opened Wikipedia page for file signatures")

        if isinstance(event, str) and event == "-LOG_DIR-":
            # User selected a new log directory
            if values["-LOG_DIR-"]:
                log_dir = setup_logging(values["-LOG_DIR-"])
                window["-STATUS-"].update(f"Log directory set to: {log_dir}")
                logging.info(f"Log directory changed to: {log_dir}")

        # Handle mode toggle
        if isinstance(event, str) and (event == "-MANUAL_MODE-" or event == "-AUTO_MODE-"):
            is_auto_mode = values["-AUTO_MODE-"]

            # Stop auto monitoring if switching to manual mode
            if not is_auto_mode and auto_monitor.is_monitoring:
                auto_monitor.stop_monitoring()
                window["-STATUS-"].update("Auto monitoring stopped. Switched to manual mode.")

            # If switching to auto mode and a directory is already selected, start monitoring
            elif is_auto_mode and selected_directory:
                # Get hex and text signatures
                hex_signatures_text = values["-HEX_SIGNATURES-"].strip()
                text_signatures_text = values["-TEXT_SIGNATURES-"].strip()

                # Parse hex signatures
                hex_signatures = [line.strip() for line in hex_signatures_text.split("\n") if line.strip()]

                # Parse text signatures
                text_signatures = [line.strip() for line in text_signatures_text.split("\n") if line.strip()]

                # Get match all setting
                match_all = values["-MATCH_ALL-"]

                # Get maximum load bytes
                try:
                    max_load_bytes = int(values["-MAX_LOAD_BYTES-"])
                    if max_load_bytes <= 0:
                        max_load_bytes = 1024  # Default if invalid
                except ValueError:
                    max_load_bytes = 1024  # Default if not a number

                # Check if we have signatures
                has_signatures = bool(hex_signatures or text_signatures)

                if has_signatures:
                    # Create matches subfolder if it doesn't exist
                    matches_dir = os.path.join(selected_directory, "matches")
                    if not os.path.exists(matches_dir):
                        try:
                            os.makedirs(matches_dir)
                            logging.info(f"Created matches directory: {matches_dir}")
                        except Exception as e:
                            logging.error(f"Error creating matches directory: {e}")
                            sg.popup_error(f"Error creating matches directory: {e}")

                    # Define callback function for processing files
                    def process_file_callback(file_path: str) -> None:
                        """
                        Process a file detected by the auto monitor.

                        Args:
                            file_path: Path to the file to process
                        """
                        # Skip files in the matches directory
                        if os.path.dirname(file_path) == matches_dir:
                            return

                        # Process the file and move it if it matches
                        process_file_auto(file_path, hex_signatures, text_signatures, match_all, max_load_bytes, matches_dir)

                    # Stop monitoring if already monitoring
                    if auto_monitor.is_monitoring:
                        auto_monitor.stop_monitoring()

                    # Get file extensions and convert newlines to commas
                    file_extensions = values["-FILE_EXTENSIONS-"].replace("\n", ",").strip()

                    # Start monitoring the directory
                    if auto_monitor.start_monitoring(
                        selected_directory,
                        process_file_callback,
                        hex_signatures,
                        text_signatures,
                        match_all,
                        max_load_bytes,
                        file_extensions
                    ):
                        # Perform initial scan of existing files
                        window["-STATUS-"].update(f"Auto monitoring directory: {selected_directory}. Performing initial scan...")
                        recursive = values["-RECURSIVE-"]
                        scan_directory_and_process(
                            selected_directory,
                            hex_signatures,
                            text_signatures,
                            match_all,
                            max_load_bytes,
                            matches_dir,
                            recursive,
                            file_extensions
                        )
                        window["-STATUS-"].update(f"Auto monitoring directory: {selected_directory}")
                    else:
                        window["-STATUS-"].update("Failed to start auto monitoring")

            # Update UI based on selected mode
            update_ui_for_mode(window, is_auto_mode, selected_directory)

            # Update analyze button state and info banner
            has_signatures, has_files = update_analyze_button_state(
                window,
                values["-HEX_SIGNATURES-"],
                values["-TEXT_SIGNATURES-"],
                selected_files,
                selected_directory,
                is_auto_mode
            )
            update_info_banner(window, selected_files, selected_directory, has_signatures, has_files, is_auto_mode)

        if isinstance(event, str) and event == "-FILE_PATH-":
            selected_files = values["-FILE_PATH-"].split(";") if values["-FILE_PATH-"] else []
            selected_directory = None  # Clear directory selection when files are selected
            logging.info(f"Selected {len(selected_files)} files")

            # Update Analyze button state and info banner
            has_signatures, has_files = update_analyze_button_state(
                window,
                values["-HEX_SIGNATURES-"],
                values["-TEXT_SIGNATURES-"],
                selected_files,
                selected_directory,
                is_auto_mode
            )
            update_info_banner(window, selected_files, selected_directory, has_signatures, has_files, is_auto_mode)

        if isinstance(event, str) and event == "-DIR_PATH-":
            selected_directory = values["-DIR_PATH-"]
            selected_files = []  # Clear file selection when directory is selected
            logging.info(f"Selected directory: {selected_directory}")

            # Get hex and text signatures
            hex_signatures_text = values["-HEX_SIGNATURES-"].strip()
            text_signatures_text = values["-TEXT_SIGNATURES-"].strip()

            # Parse hex signatures
            hex_signatures = [line.strip() for line in hex_signatures_text.split("\n") if line.strip()]

            # Parse text signatures
            text_signatures = [line.strip() for line in text_signatures_text.split("\n") if line.strip()]

            # Get match all setting
            match_all = values["-MATCH_ALL-"]

            # Get maximum load bytes
            try:
                max_load_bytes = int(values["-MAX_LOAD_BYTES-"])
                if max_load_bytes <= 0:
                    max_load_bytes = 1024  # Default if invalid
            except ValueError:
                max_load_bytes = 1024  # Default if not a number

            # If in auto mode, start monitoring the directory
            if is_auto_mode and selected_directory:
                # Create matches subfolder if it doesn't exist
                matches_dir = os.path.join(selected_directory, "matches")
                if not os.path.exists(matches_dir):
                    try:
                        os.makedirs(matches_dir)
                        logging.info(f"Created matches directory: {matches_dir}")
                    except Exception as e:
                        logging.error(f"Error creating matches directory: {e}")
                        sg.popup_error(f"Error creating matches directory: {e}")

                # Define callback function for processing files
                def process_file_callback(file_path: str) -> None:
                    """
                    Process a file detected by the auto monitor.

                    Args:
                        file_path: Path to the file to process
                    """
                    # Skip files in the matches directory
                    if os.path.dirname(file_path) == matches_dir:
                        return

                    # Process the file and move it if it matches
                    process_file_auto(file_path, hex_signatures, text_signatures, match_all, max_load_bytes, matches_dir)

                # Stop monitoring if already monitoring
                if auto_monitor.is_monitoring:
                    auto_monitor.stop_monitoring()

                # Get file extensions and convert newlines to commas
                file_extensions = values["-FILE_EXTENSIONS-"].replace("\n", ",").strip()

                # Start monitoring the directory
                if auto_monitor.start_monitoring(
                    selected_directory,
                    process_file_callback,
                    hex_signatures,
                    text_signatures,
                    match_all,
                    max_load_bytes,
                    file_extensions
                ):
                    # Perform initial scan of existing files
                    window["-STATUS-"].update(f"Auto monitoring directory: {selected_directory}. Performing initial scan...")
                    recursive = values["-RECURSIVE-"]
                    scan_directory_and_process(
                        selected_directory,
                        hex_signatures,
                        text_signatures,
                        match_all,
                        max_load_bytes,
                        matches_dir,
                        recursive,
                        file_extensions
                    )
                    window["-STATUS-"].update(f"Auto monitoring directory: {selected_directory}")
                else:
                    window["-STATUS-"].update("Failed to start auto monitoring")

            # Update Analyze button state and info banner
            has_signatures, has_files = update_analyze_button_state(
                window,
                values["-HEX_SIGNATURES-"],
                values["-TEXT_SIGNATURES-"],
                selected_files,
                selected_directory,
                is_auto_mode
            )
            update_info_banner(window, selected_files, selected_directory, has_signatures, has_files, is_auto_mode)

        # Handle signature input changes
        if isinstance(event, str) and event in ["-HEX_SIGNATURES-", "-TEXT_SIGNATURES-", "-MATCH_ALL-", "-MAX_LOAD_BYTES-"]:
            # Get hex and text signatures
            hex_signatures_text = values["-HEX_SIGNATURES-"].strip()
            text_signatures_text = values["-TEXT_SIGNATURES-"].strip()

            # Parse hex signatures
            hex_signatures = [line.strip() for line in hex_signatures_text.split("\n") if line.strip()]

            # Parse text signatures
            text_signatures = [line.strip() for line in text_signatures_text.split("\n") if line.strip()]

            # Get match all setting
            match_all = values["-MATCH_ALL-"]

            # Get maximum load bytes
            try:
                max_load_bytes = int(values["-MAX_LOAD_BYTES-"])
                if max_load_bytes <= 0:
                    max_load_bytes = 1024  # Default if invalid
            except ValueError:
                max_load_bytes = 1024  # Default if not a number

            # Update automonitor with new signatures if in auto mode
            if is_auto_mode and auto_monitor.is_monitoring:
                auto_monitor.update_signatures(
                    hex_signatures,
                    text_signatures,
                    match_all,
                    max_load_bytes
                )

            # Update Analyze button state and info banner
            has_signatures, has_files = update_analyze_button_state(
                window,
                values["-HEX_SIGNATURES-"],
                values["-TEXT_SIGNATURES-"],
                selected_files,
                selected_directory,
                is_auto_mode
            )
            update_info_banner(window, selected_files, selected_directory, has_signatures, has_files, is_auto_mode)

        if isinstance(event, str) and event == "-RESET-":
            # Stop auto monitoring if active
            if is_auto_mode and auto_monitor.is_monitoring:
                auto_monitor.stop_monitoring()

            # Reset mode to manual
            is_auto_mode = False
            window["-MANUAL_MODE-"].update(value=True)
            window["-AUTO_MODE-"].update(value=False)

            # Clear all signatures and reset to defaults
            window["-HEX_SIGNATURES-"].update("50 4B 03 04\n50 4B 05 06\n50 4B 07 08")  # Default hex signatures
            window["-TEXT_SIGNATURES-"].update("voltage\nencrypt")  # Reset to default text signatures
            window["-MATCH_ALL-"].update(False)  # Reset match all checkbox
            window["-MAX_LOAD_BYTES-"].update("1024")  # Reset max load bytes
            window["-RECURSIVE-"].update(False)  # Reset recursive checkbox

            # Clear selected files and directory
            selected_files = []
            selected_directory = None

            # Clear results table
            window["-RESULTS_TABLE-"].update([])
            window["-STATUS-"].update("Reset completed. All settings restored to defaults.")

            # Disable export and organize buttons
            window["-EXPORT_CSV-"].update(disabled=True)
            window["-ORGANIZE_FILES-"].update(disabled=True)

            # Delete saved state file if it exists
            state_file = get_state_file_path()
            if os.path.exists(state_file):
                try:
                    os.remove(state_file)
                    logging.info("Saved state file deleted")
                except Exception as e:
                    logging.error(f"Error deleting state file: {e}")

            # Update UI for manual mode
            update_ui_for_mode(window, is_auto_mode)

            # Update Analyze button state and info banner after reset
            has_signatures, has_files = update_analyze_button_state(
                window,
                window["-HEX_SIGNATURES-"].get(),
                window["-TEXT_SIGNATURES-"].get(),
                selected_files,
                selected_directory,
                is_auto_mode
            )
            update_info_banner(window, selected_files, selected_directory, has_signatures, has_files, is_auto_mode)

        if isinstance(event, str) and event == "-ANALYZE-":
            # Initialize variables that might be referenced later
            table_data = []

            # Get hex and text signatures
            hex_signatures_text = values["-HEX_SIGNATURES-"].strip()
            text_signatures_text = values["-TEXT_SIGNATURES-"].strip()

            # Check if we have both signatures and files/directories
            if not (hex_signatures_text or text_signatures_text):
                window["-INFO_BANNER-"].update("Please enter at least one hex or text signature")
                continue

            if not (selected_files or selected_directory):
                window["-INFO_BANNER-"].update("Please select file(s) or choose a directory")
                continue

            # Save state to ensure latest inputs are used
            save_state(values, selected_files, selected_directory)

            # Parse hex signatures
            hex_signatures = [line.strip() for line in hex_signatures_text.split("\n") if line.strip()]

            # Parse text signatures
            text_signatures = [line.strip() for line in text_signatures_text.split("\n") if line.strip()]

            # Get match all setting
            match_all = values["-MATCH_ALL-"]

            # Get maximum load bytes
            try:
                max_load_bytes = int(values["-MAX_LOAD_BYTES-"])
                if max_load_bytes <= 0:
                    max_load_bytes = 1024  # Default if invalid
            except ValueError:
                max_load_bytes = 1024  # Default if not a number

            # Get files to process
            files_to_process = []

            # Get file extensions and convert newlines to commas
            file_extensions = values["-FILE_EXTENSIONS-"].replace("\n", ",").strip()

            # Process file extensions
            extensions = []
            if file_extensions and file_extensions.strip() not in ["*.*", ".*"]:
                extensions = [ext.strip().lower() for ext in file_extensions.split(",") if ext.strip()]
                # Add leading dot if missing
                extensions = ["." + ext if not ext.startswith(".") else ext for ext in extensions]

            if selected_files:
                # Filter selected files based on extensions
                if extensions:
                    files_to_process = []
                    for file_path in selected_files:
                        file_ext = os.path.splitext(file_path)[1].lower()
                        if file_ext in extensions:
                            files_to_process.append(file_path)
                else:
                    files_to_process = selected_files
            elif selected_directory:
                # Show status message while collecting files
                window["-STATUS-"].update("Scanning directory for files...")
                window.refresh()

                recursive = values["-RECURSIVE-"]

                files_to_process = get_all_files_in_directory(selected_directory, recursive, file_extensions)
                logging.info(f"Found {len(files_to_process)} files in directory")

            if not files_to_process:
                window["-STATUS-"].update("No files to process")
                window["-RESULTS_TABLE-"].update([["No files to process", "", "", "", ""]])
                window["-EXPORT_CSV-"].update(disabled=True)
                window["-ORGANIZE_FILES-"].update(disabled=True)
                continue

            # Setup progress bar
            window["-PROGRESS-"].update(visible=True, current_count=0)
            window["-STATUS-"].update(f"Processing 0 of {len(files_to_process)} files...")
            window["-RESULTS_TABLE-"].update([["Processing...", "", "", "", ""]])
            window.refresh()

            # Define progress callback function
            def update_progress(percent, status_text):
                window["-PROGRESS-"].update(current_count=percent)
                window["-STATUS-"].update(status_text)
                window.refresh()

            # Process the files with progress updates
            results = process_files_with_progress(
                files_to_process,
                hex_signatures,
                text_signatures,
                match_all,
                max_load_bytes,
                update_progress
            )

            # Hide progress bar when done
            window["-PROGRESS-"].update(visible=False)
            window["-STATUS-"].update(f"Completed processing {len(files_to_process)} files")

            # Update info banner with results summary
            window["-INFO_BANNER-"].update(f"Processed {len(files_to_process)} files. Found matches in {sum(1 for r in results if r['has_hex_signature'] or r['text_match_result'])} files.")

            # Format results for the table
            table_data = []
            for result in results:
                table_data.append([
                    result["file_name"],
                    "Yes" if result["has_hex_signature"] else "No",
                    "Yes" if result["text_match_result"] else "No",
                    ", ".join(result["hex_matches"]),
                    ", ".join(result["text_matches"])
                ])

            # Update the results table
            window["-RESULTS_TABLE-"].update(table_data)

            # Enable the Export to CSV and Organize Files buttons if there are results
            if table_data:
                window["-EXPORT_CSV-"].update(disabled=False)
                window["-ORGANIZE_FILES-"].update(disabled=False)
            else:
                window["-EXPORT_CSV-"].update(disabled=True)
                window["-ORGANIZE_FILES-"].update(disabled=True)

        if isinstance(event, str) and event == "-EXPORT_CSV-":
            # Get a file path to save the CSV
            save_path = sg.popup_get_file(
                "Save CSV File",
                save_as=True,
                file_types=(("CSV Files", "*.csv"),),
                default_extension=".csv",
                no_window=True
            )

            if save_path:
                try:
                    # Use the existing table_data variable instead of trying to get it from the table
                    # This ensures we're using the same data that was displayed in the table
                    headers = RESULT_TABLE_HEADERS

                    # Write to CSV
                    with open(save_path, 'w', newline='') as csvfile:
                        writer = csv.writer(csvfile)
                        writer.writerow(headers)
                        # Ensure all data is properly formatted as strings
                        formatted_data = []
                        for row in table_data:
                            formatted_row = [str(cell) for cell in row]
                            formatted_data.append(formatted_row)
                        writer.writerows(formatted_data)

                    sg.popup("Export Successful", f"Results exported to {save_path}")
                except Exception as e:
                    sg.popup_error(f"Error exporting to CSV: {e}")

        if isinstance(event, str) and event == "-ORGANIZE_FILES-":
            # Initialize variables that might be referenced later
            moved_files = 0
            errors = []

            # Get the matched files from the results
            matched_files = []
            for result in results:
                # Include files that match either hex or text signatures
                if result["has_hex_signature"] or result["text_match_result"]:
                    matched_files.append(result["file_path"])

            if not matched_files:
                sg.popup_error("No matched files to organize")
                continue

            # Determine the target directory
            # Default is a "matched" subfolder in the application directory
            default_dir = os.path.join(get_application_path(), "matched")

            # Ask user for target directory
            target_dir = sg.popup_get_folder(
                "Select target directory for matched files",
                default_path=default_dir,
                no_window=True
            )

            if not target_dir:
                continue  # User cancelled

            # Create the target directory if it doesn't exist
            if not os.path.exists(target_dir):
                try:
                    os.makedirs(target_dir)
                except Exception as e:
                    sg.popup_error(f"Error creating directory: {e}")
                    continue

            # Move the matched files
            moved_files = 0
            errors = []

            for file_path in matched_files:
                try:
                    # Get the filename without path
                    filename = os.path.basename(file_path)
                    # Create the destination path
                    dest_path = os.path.join(target_dir, filename)

                    # Handle file name conflicts
                    if os.path.exists(dest_path):
                        base, ext = os.path.splitext(filename)
                        counter = 1
                        while os.path.exists(dest_path):
                            new_filename = f"{base}_{counter}{ext}"
                            dest_path = os.path.join(target_dir, new_filename)
                            counter += 1

                    # Move the file
                    shutil.move(file_path, dest_path)
                    moved_files += 1
                except Exception as e:
                    errors.append(f"{file_path}: {str(e)}")

            # Show results
            if errors:
                error_message = "\n".join(errors[:10])  # Show first 10 errors
                if len(errors) > 10:
                    error_message += f"\n... and {len(errors) - 10} more errors"
                sg.popup_error(f"Errors occurred while moving files:\n{error_message}")

            if moved_files > 0:
                sg.popup("Organization Complete", f"Successfully moved {moved_files} files to {target_dir}")

                # Disable the buttons since the files have been moved
                window["-EXPORT_CSV-"].update(disabled=True)
                window["-ORGANIZE_FILES-"].update(disabled=True)

                # Update the status
                window["-STATUS-"].update(f"Moved {moved_files} files to {target_dir}")

                # Clear the results table
                window["-RESULTS_TABLE-"].update([["Files have been moved", "", "", "", ""]])

        # Handle table header clicks for sorting
        if isinstance(event, tuple):
            # TABLE CLICKED Event has value in format ('-TABLE-', '+CLICKED+', (row,col))
            if event[0] == "-RESULTS_TABLE-":
                if event[2][0] == -1 and event[2][1] != -1:  # Header was clicked and wasn't the "row" column
                    col_num_clicked = event[2][1]
                    try:
                        # Sort the table data by the clicked column
                        if 'table_data' in locals() and table_data:
                            global LAST_SORTED_COLUMN, SORT_REVERSE

                            # Toggle sort direction if clicking the same column again
                            if LAST_SORTED_COLUMN == col_num_clicked:
                                SORT_REVERSE = not SORT_REVERSE
                            else:
                                # New column, start with ascending sort
                                SORT_REVERSE = False

                            # Update the last sorted column
                            LAST_SORTED_COLUMN = col_num_clicked

                            # Sort the table with the appropriate direction
                            new_table = sort_table(table_data, (col_num_clicked, 0), SORT_REVERSE)
                            window["-RESULTS_TABLE-"].update(new_table)
                            table_data = new_table

                            # Get the column name from the global headers
                            headers = RESULT_TABLE_HEADERS
                            # Get the column name from the headers
                            column_name = headers[col_num_clicked]
                            sort_direction = "descending" if SORT_REVERSE else "ascending"
                            window["-STATUS-"].update(f"Sorted table by column: {column_name} ({sort_direction})")
                    except Exception as e:
                        logging.error(f"Error sorting table: {e}")
                        window["-STATUS-"].update(f"Error sorting table: {e}")

    window.close()

if __name__ == "__main__":
    main()
