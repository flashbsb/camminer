import os
import sys
import time
from datetime import datetime

class Colors:
    CYAN = '\033[96m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'

    @classmethod
    def setup_colors(cls):
        # Enable VT100 processing on Windows terminal
        if os.name == 'nt':
            os.system('')
        # Disable colors if stdout is redirected or NO_COLOR environment variable is set
        if not sys.stdout.isatty() or os.getenv('NO_COLOR'):
            cls.CYAN = ''
            cls.BLUE = ''
            cls.GREEN = ''
            cls.YELLOW = ''
            cls.RED = ''
            cls.MAGENTA = ''
            cls.BOLD = ''
            cls.DIM = ''
            cls.RESET = ''

Colors.setup_colors()

class Logger:
    def __init__(self, verbose=False, log_to_file=False, log_filepath=None):
        self.verbose = verbose
        self.log_to_file = log_to_file
        self.log_filepath = log_filepath

        if self.log_to_file and self.log_filepath:
            log_dir = os.path.dirname(self.log_filepath)
            if log_dir:
                os.makedirs(log_dir, exist_ok=True)
            with open(self.log_filepath, 'a', encoding='utf-8') as f:
                f.write(f"=== CamMiner Session Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n")

    def _write_file(self, level, msg):
        if self.log_to_file and self.log_filepath:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            # Clean ANSI colors for log file
            clean_msg = msg
            for col in [Colors.CYAN, Colors.BLUE, Colors.GREEN, Colors.YELLOW, Colors.RED, Colors.MAGENTA, Colors.BOLD, Colors.DIM, Colors.RESET]:
                clean_msg = clean_msg.replace(col, '')
            try:
                with open(self.log_filepath, 'a', encoding='utf-8') as f:
                    f.write(f"[{timestamp}] [{level:<7}] {clean_msg}\n")
            except Exception:
                pass

    def info(self, msg):
        formatted = f"{Colors.CYAN}[*]{Colors.RESET} {msg}"
        print(formatted)
        self._write_file("INFO", msg)

    def success(self, msg):
        formatted = f"{Colors.GREEN}[+]{Colors.RESET} {msg}"
        print(formatted)
        self._write_file("SUCCESS", msg)

    def warning(self, msg):
        formatted = f"{Colors.YELLOW}[-]{Colors.RESET} {msg}"
        print(formatted, file=sys.stderr)
        self._write_file("WARN", msg)

    def error(self, msg):
        formatted = f"{Colors.RED}[!]{Colors.RESET} {msg}"
        print(formatted, file=sys.stderr)
        self._write_file("ERROR", msg)

    def debug(self, msg):
        self._write_file("DEBUG", msg)
        if self.verbose:
            formatted = f"{Colors.DIM}[DEBUG]{Colors.RESET} {msg}"
            print(formatted)

    def stage(self, current, total, title):
        banner = f"\n{Colors.BOLD}{Colors.MAGENTA}=== STAGE [{current}/{total}]: {title.upper()} ==={Colors.RESET}"
        print(banner)
        self._write_file("STAGE", f"=== STAGE [{current}/{total}]: {title.upper()} ===")

    def progress(self, current, total, prefix="Progress", item=""):
        percent = (current / max(1, total)) * 100
        item_str = f" ({item})" if item else ""
        bar = f"{Colors.BLUE}[{current}/{total}]{Colors.RESET} {percent:5.1f}%{item_str}"
        sys.stdout.write(f"\r{Colors.CYAN}[*]{Colors.RESET} {prefix}: {bar}")
        sys.stdout.flush()
        if current >= total:
            sys.stdout.write("\n")
            sys.stdout.flush()

# Default shared logger instance
logger = Logger()
