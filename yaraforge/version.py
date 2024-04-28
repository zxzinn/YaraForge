__version__ = '0.1.11b1'

from yaraforge.metadata import pathnames
from yaraforge.utils.logger import get_global_logger

logger = get_global_logger(pathnames['logger_dir'])


def get_version():
    """
    Get the version
    :return: The version
    """
    logger.info(f"Getting version {__version__}")
    return __version__
