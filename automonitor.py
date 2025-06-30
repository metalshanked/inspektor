import os
import time
import threading
import logging
from typing import List, Dict, Callable, Optional, Set
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent

class FileChangeHandler(FileSystemEventHandler):
    """Handler for file system events that processes files based on specified signatures."""

    def __init__(self, 
                 process_callback: Callable[[str], None],
                 hex_signatures: List[str],
                 text_signatures: List[str],
                 match_all_text: bool,
                 max_load_bytes: int = 1024,
                 file_extensions: str = ""):
        """
        Initialize the file change handler.

        Args:
            process_callback: Callback function to process a file
            hex_signatures: List of hex signatures to check for
            text_signatures: List of text signatures to check for
            match_all_text: Whether all text signatures must match
            max_load_bytes: Maximum number of bytes to load from each file
            file_extensions: Comma-separated list of file extensions to scan (e.g., ".txt,.pdf,.docx")
                             If empty, "*.*", or ".*", all files are included
        """
        self.process_callback: Callable[[str], None] = process_callback
        self.hex_signatures: List[str] = hex_signatures
        self.text_signatures: List[str] = text_signatures
        self.match_all_text: bool = match_all_text
        self.max_load_bytes: int = max_load_bytes
        self.file_extensions: str = file_extensions
        # Process file extensions
        self.extensions: List[str] = []
        if file_extensions and file_extensions.strip() not in ["*.*", ".*"]:
            self.extensions = [ext.strip().lower() for ext in file_extensions.split(",") if ext.strip()]
            # Add leading dot if missing
            self.extensions = ["." + ext if not ext.startswith(".") else ext for ext in self.extensions]
        # Keep track of recently processed files to avoid duplicate processing
        self.recently_processed: Set[str] = set()
        self.lock: threading.Lock = threading.Lock()

    def on_created(self, event: FileCreatedEvent) -> None:
        """
        Handle file created event.

        Args:
            event: The file created event to handle
        """
        if not event.is_directory and isinstance(event, FileCreatedEvent):
            self._handle_file_event(event.src_path)

    def on_modified(self, event: FileModifiedEvent) -> None:
        """
        Handle file modified event.

        Args:
            event: The file modified event to handle
        """
        if not event.is_directory and isinstance(event, FileModifiedEvent):
            self._handle_file_event(event.src_path)

    def _handle_file_event(self, file_path: str) -> None:
        """
        Handle a file event by processing the file.

        Args:
            file_path: Path to the file to process
        """
        # Check if the file extension matches the specified extensions
        if self.extensions:
            file_ext = os.path.splitext(file_path)[1].lower()
            if file_ext not in self.extensions:
                return

        with self.lock:
            # Check if this file was recently processed to avoid duplicates
            if file_path in self.recently_processed:
                return

            # Add to recently processed set
            self.recently_processed.add(file_path)

            # Schedule removal from recently processed set after a delay
            threading.Timer(2.0, self._remove_from_processed, args=[file_path]).start()

        # Process the file
        self.process_callback(file_path)

    def _remove_from_processed(self, file_path: str) -> None:
        """
        Remove a file from the recently processed set.

        Args:
            file_path: Path to the file to remove
        """
        with self.lock:
            self.recently_processed.discard(file_path)

    def update_signatures(self, 
                         hex_signatures: List[str],
                         text_signatures: List[str],
                         match_all_text: bool,
                         max_load_bytes: int = 1024,
                         file_extensions: str = ""):
        """
        Update the signatures used for file matching.

        Args:
            hex_signatures: List of hex signatures to check for
            text_signatures: List of text signatures to check for
            match_all_text: Whether all text signatures must match
            max_load_bytes: Maximum number of bytes to load from each file
            file_extensions: Comma-separated list of file extensions to scan (e.g., ".txt,.pdf,.docx")
                             If empty, "*.*", or ".*", all files are included
        """
        with self.lock:
            self.hex_signatures = hex_signatures
            self.text_signatures = text_signatures
            self.match_all_text = match_all_text
            self.max_load_bytes = max_load_bytes
            self.file_extensions = file_extensions

            # Process file extensions
            self.extensions = []
            if file_extensions and file_extensions.strip() not in ["*.*", ".*"]:
                self.extensions = [ext.strip().lower() for ext in file_extensions.split(",") if ext.strip()]
                # Add leading dot if missing
                self.extensions = ["." + ext if not ext.startswith(".") else ext for ext in self.extensions]

class AutoMonitor:
    """
    Class for automatically monitoring a directory for file changes.

    This class provides functionality to watch a directory for new or modified files
    and process them according to specified signature matching criteria.
    """

    def __init__(self):
        """Initialize the auto monitor with default values."""
        self.observer: Optional[Observer] = None
        self.handler: Optional[FileChangeHandler] = None
        self.is_monitoring: bool = False
        self.monitor_thread: Optional[threading.Thread] = None

    def start_monitoring(self, 
                        directory_path: str,
                        process_callback: Callable[[str], None],
                        hex_signatures: List[str],
                        text_signatures: List[str],
                        match_all_text: bool,
                        max_load_bytes: int = 1024,
                        file_extensions: str = "") -> bool:
        """
        Start monitoring a directory for file changes.

        Args:
            directory_path: Path to the directory to monitor
            process_callback: Callback function to process a file
            hex_signatures: List of hex signatures to check for
            text_signatures: List of text signatures to check for
            match_all_text: Whether all text signatures must match
            max_load_bytes: Maximum number of bytes to load from each file
            file_extensions: Comma-separated list of file extensions to scan (e.g., ".txt,.pdf,.docx")
                             If empty, "*.*", or ".*", all files are included

        Returns:
            True if monitoring started successfully, False otherwise
        """
        if self.is_monitoring:
            self.stop_monitoring()

        if not os.path.isdir(directory_path):
            return False

        try:
            self.handler = FileChangeHandler(
                process_callback,
                hex_signatures,
                text_signatures,
                match_all_text,
                max_load_bytes,
                file_extensions
            )

            self.observer = Observer()
            self.observer.schedule(self.handler, directory_path, recursive=False)
            self.observer.start()
            self.is_monitoring = True

            # Start a thread to keep the observer running
            self.monitor_thread = threading.Thread(target=self._monitor_thread, daemon=True)
            self.monitor_thread.start()

            return True
        except Exception as e:
            logging.error(f"Error starting monitoring: {e}")
            self.stop_monitoring()
            return False

    def stop_monitoring(self) -> bool:
        """
        Stop monitoring the directory.

        Returns:
            True if monitoring was stopped successfully, False otherwise
        """
        if not self.is_monitoring:
            return True

        try:
            if self.observer:
                self.observer.stop()
                self.observer.join()
                self.observer = None

            self.handler = None
            self.is_monitoring = False
            return True
        except Exception as e:
            logging.error(f"Error stopping monitoring: {e}")
            return False

    def update_signatures(self,
                         hex_signatures: List[str],
                         text_signatures: List[str],
                         match_all_text: bool,
                         max_load_bytes: int = 1024,
                         file_extensions: str = "") -> bool:
        """
        Update the signatures used for file matching.

        Args:
            hex_signatures: List of hex signatures to check for
            text_signatures: List of text signatures to check for
            match_all_text: Whether all text signatures must match
            max_load_bytes: Maximum number of bytes to load from each file
            file_extensions: Comma-separated list of file extensions to scan (e.g., ".txt,.pdf,.docx")
                             If empty, "*.*", or ".*", all files are included

        Returns:
            True if signatures were updated successfully, False otherwise
        """
        if not self.is_monitoring or not self.handler:
            return False

        try:
            self.handler.update_signatures(
                hex_signatures,
                text_signatures,
                match_all_text,
                max_load_bytes,
                file_extensions
            )
            return True
        except Exception as e:
            logging.error(f"Error updating signatures: {e}")
            return False

    def _monitor_thread(self) -> None:
        """
        Thread function to keep the observer running.

        This method runs in a separate thread and continuously checks if the observer
        is still alive. If an exception occurs, it logs the error and stops monitoring.
        """
        try:
            while self.is_monitoring and self.observer and self.observer.is_alive():
                time.sleep(1)
        except Exception as e:
            logging.error(f"Error in monitor thread: {e}")
        finally:
            self.is_monitoring = False
