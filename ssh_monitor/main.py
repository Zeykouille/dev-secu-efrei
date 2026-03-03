import sys
from parser import parse_line
from detector import process_event
from realtime import follow
from config import LOG_FILE, REALTIME_MODE
from logger_config import setup_logger

logger = setup_logger()

def main():
    try:
        with open(LOG_FILE, "r") as f:

            if REALTIME_MODE:
                lines = follow(f)
            else:
                lines = f

            for line in lines:
                event = parse_line(line)
                if event:
                    process_event(event)

    except FileNotFoundError:
        logger.error("Log file not found")
        sys.exit(1)

    except PermissionError:
        logger.error("Permission denied")
        sys.exit(1)

    except Exception as e:
        logger.exception("Unexpected error")
        sys.exit(1)

if __name__ == "__main__":
    main()
