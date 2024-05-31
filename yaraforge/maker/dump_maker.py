import json
from pathlib import Path

import capa

from yaraforge.metadata import pathnames
from yaraforge.utils.common import custom_json_serializer
from yaraforge.utils.logger import get_global_logger

logger = get_global_logger(pathnames['logger_dir'])


class DumpMaker:
    """
    A class to create a pretty dump of the CAPA analysis results.

    This class takes a file hash (MD5) as input and uses it to load the cached CAPA analysis results.
    It then creates a pretty dump of the CAPA analysis results in JSON format and saves it to a file.
    """

    def __init__(self, file_hex_md5):
        """
        Initialize the DumpMaker instance with the file hash (MD5).

        Args:
            file_hex_md5 (str): The MD5 hash of the file.
        """
        self.file_hex_md5 = file_hex_md5
        self.logger = get_global_logger(pathnames['logger_dir'])

    def make_pretty_dump(self):
        """
        Main function to create a pretty dump of the CAPA analysis results.

        This function loads the cached CAPA analysis results, creates a pretty dump in JSON format,
        and saves it to a file with the naming convention "{file_hash}_pretty_dump.json".

        Returns:
            self: The DumpMaker instance.
        """
        self.logger.info(f"Starting pretty dump for {self.file_hex_md5}.")
        try:
            result_document = capa.ida.helpers.load_and_verify_cached_results()
            if result_document:
                json_data = json.dumps(result_document.model_dump(), default=custom_json_serializer, indent=4,
                                       ensure_ascii=False)

                pretty_dump = Path(pathnames['pretty_dump_dir']) / f"{self.file_hex_md5}_pretty_dump.json"
                with pretty_dump.open('w', encoding='utf-8') as file:
                    file.write(json_data)
                self.logger.info(f"PrettyDump has been saved to {pretty_dump}")
            else:
                self.logger.error("Failed to find or load CAPA results.")
        except Exception as e:
            self.logger.error(f"Error during pretty dump: {e}")
        return self