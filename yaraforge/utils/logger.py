import logging
import os
from datetime import datetime
from pathlib import Path

from yaraforge.metadata import pathnames, metadata

logger = None


def initialize_logger():
    """
    Initialize the logger for the YaraForge plugin.

    This function sets up the logging configuration, including the log directory, log file name,
    log level, and log format. It creates the log directory if it doesn't exist and configures
    the logging using the `logging.basicConfig()` function.

    If an exception occurs during the logger initialization, it prints an error message.
    """
    try:
        log_dir = pathnames['logger_dir']
        Path(log_dir).mkdir(parents=True, exist_ok=True)

        log_filename = datetime.now().strftime("%Y%m%d_%H%M%S") + ".log"
        log_filepath = os.path.join(log_dir, log_filename)

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
    Get the global logger instance for the YaraForge plugin.

    This function retrieves the global logger instance for the YaraForge plugin. If the logger
    hasn't been initialized yet, it creates the log directory if it doesn't exist, sets up the
    log file path, and configures the logger with the specified name, log level, and log format.

    The logger is configured to not propagate messages to parent loggers by setting `propagate`
    to `False`. This ensures that the log messages are only handled by the YaraForge logger.

    If an exception occurs while obtaining the global logger, it prints an error message and
    returns `None`.

    Args:
        log_dir (str, optional): The directory path for storing the log files.
            Defaults to `pathnames['logger_dir']`.
        name (str, optional): The name of the logger. Defaults to 'yaraforge'.
        level (int, optional): The log level for the logger. Defaults to `logging.INFO`.

    Returns:
        logging.Logger: The global logger instance for the YaraForge plugin, or `None` if an error occurs.
    """
    global logger
    try:
        if logger is None:
            os.makedirs(log_dir, exist_ok=True)
            datetime_str = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_file_name = f"{datetime_str}.log"
            log_file_path = Path(log_dir) / log_file_name

            logger = logging.getLogger(name)
            logger.setLevel(level)
            logger.propagate = False  # Turn off propagation

            if not logger.handlers:
                handler = logging.FileHandler(log_file_path)
                formatter = logging.Formatter(
                    f'%(asctime)s - {metadata["plugin_name"]} - [%(filename)s] - %(levelname)s '
                    f'- %(message)s')
                handler.setFormatter(formatter)
                logger.addHandler(handler)

        return logger
    except Exception as e:
        print(f"Error occurred while obtaining global logger: {e}")
        return None