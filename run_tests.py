import os
import sys
import pytest
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import re

class TestRunner(FileSystemEventHandler):
    def __init__(self):
        self.last_run = 0
        self.debounce_time = 1.0  # seconds
        
    def on_modified(self, event):
        if event.is_directory:
            return
            
        # Ignore non-Python files
        if not event.src_path.endswith('.py'):
            return
            
        # Debounce multiple events
        current_time = time.time()
        if current_time - self.last_run < self.debounce_time:
            return
            
        self.last_run = current_time
        
        # Get the modified file path
        modified_file = event.src_path
        
        # Determine which tests to run based on the modified file
        if 'tests' in modified_file:
            # If a test file was modified, run only that test file
            test_path = modified_file
        else:
            # If a source file was modified, find and run related test files
            source_file = os.path.basename(modified_file)
            source_name = os.path.splitext(source_file)[0]
            
            # Convert source file name to test file pattern
            if source_name.startswith('test_'):
                test_pattern = source_name
            else:
                test_pattern = f'test_{source_name}'
            
            # Find related test files
            test_path = self.find_related_tests(test_pattern)
        
        # Run the tests
        self.run_tests(test_path)
    
    def find_related_tests(self, pattern):
        """Find test files related to the modified source file."""
        tests_dir = 'accounts/tests'  # Adjust this path as needed
        related_tests = []
        
        for root, _, files in os.walk(tests_dir):
            for file in files:
                if file.startswith('test_') and file.endswith('.py'):
                    if pattern in file:
                        related_tests.append(os.path.join(root, file))
        
        return related_tests[0] if related_tests else 'accounts/tests'
    
    def run_tests(self, test_path):
        """Run pytest with the specified test path."""
        print(f"\nRunning tests for: {test_path}")
        print("=" * 80)
        
        args = ['-v', test_path]
        pytest.main(args)

def watch_tests():
    event_handler = TestRunner()
    observer = Observer()
    
    # Watch both source and test directories
    paths_to_watch = [
        'accounts',
        'core',
        'myauth_project'
    ]
    
    for path in paths_to_watch:
        if os.path.exists(path):
            observer.schedule(event_handler, path, recursive=True)
    
    print("Watching for file changes... Press Ctrl+C to exit")
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--all':
        # Run all tests once
        pytest.main(['-v'])
    else:
        # Watch for changes
        watch_tests() 