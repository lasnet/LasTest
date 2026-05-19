import logging
import os

LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "pentest.log")

def init_logger():
    os.makedirs(LOG_DIR, exist_ok=True)

    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s"
    )

    logging.info("=== Pentest Platform started ===")
