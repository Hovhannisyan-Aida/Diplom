import logging
import os

os.makedirs("/app/logs", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler("/app/logs/scanner.log"),
        logging.StreamHandler()
    ],
    force=True
)
