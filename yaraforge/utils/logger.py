import logging
import os
from datetime import datetime
from pathlib import Path

from yaraforge.metadata import pathnames, metadata

logger = None


def initialize_logger():
    """
    Initialize the logger
    :return: None
    """
    try:
        # Use the logger_dir defined in the pathnames dictionary
        log_dir = pathnames['logger_dir']
        # Ensure the log directory exists
        Path(log_dir).mkdir(parents=True, exist_ok=True)

        # Create the log file name
        log_filename = datetime.now().strftime("%Y%m%d_%H%M%S") + ".log"
        log_filepath = os.path.join(log_dir, log_filename)

        # Set up logging configuration
        logging.basicConfig(
            filename=log_filepath,
            level=logging.INFO,
            format=f'%(asctime)s - {metadata["plugin_name"]} - [%(filename)s] - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    except Exception as e:
        print(f"Error occurred while initializing logger: {e}")


def get_global_logger(log_dir=pathnames['logger_dir'], name='yaraforge', level=logging.INFO):
    """
    Get the global logger
    :param log_dir:
    :param name:
    :param level:
    :return:
    """
    global logger
    try:
        if logger is None:
            # Ensure the log directory exists
            os.makedirs(log_dir, exist_ok=True)
            datetime_str = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_file_name = f"{datetime_str}.log"
            log_file_path = Path(log_dir) / log_file_name

            logger = logging.getLogger(name)
            logger.setLevel(level)
            logger.propagate = False  # Turn off propagation

            if not logger.handlers:
                # Create a file handler and formatter, then add them to the logger
                handler = logging.FileHandler(log_file_path)
                formatter = logging.Formatter(
                    f'%(asctime)s - {metadata["plugin_name"]} - [%(filename)s] - %(levelname)s '
                    f'- %(message)s')
                handler.setFormatter(formatter)
                logger.addHandler(handler)

        return logger
    except Exception as e:
        print(f"Error occurred while obtaining global logger: {e}")
        return None  # Perhaps return a default logger or None, depending on the situation


