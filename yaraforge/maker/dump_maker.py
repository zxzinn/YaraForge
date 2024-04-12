import json
from pathlib import Path

import capa

from yaraforge.metadata import pathnames
from yaraforge.utils.common import custom_json_serializer
from yaraforge.utils.logger import get_global_logger

logger = get_global_logger(pathnames['logger_dir'])


class DumpMaker:
    def __init__(self, file_hex_md5):
        """
        Initialize the DumpMaker object.
        :param file_hex_md5: The MD5 hash of the file.
        :return: None
        """
        self.file_hex_md5 = file_hex_md5
        self.logger = get_global_logger(pathnames['logger_dir'])

    def make_pretty_dump(self):
        """
        Make a pretty dump of the capa results.

        :return: None
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


