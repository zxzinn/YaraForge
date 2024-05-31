import json
from pathlib import Path

from yaraforge.metadata import pathnames
from yaraforge.utils.common import get_instructions_for_address
from yaraforge.utils.logger import get_global_logger

logger = get_global_logger(pathnames['logger_dir'])


class InstructionMaker:
    """
    A class to generate instructions based on the pretty dump file.

    This class takes a file hash (MD5) as input and uses it to locate the corresponding pretty dump file.
    It then extracts relevant information from the pretty dump file to generate instructions.
    The generated instructions are saved to a JSON file.
    """

    def __init__(self, file_hex_md5):
        """
        Initialize the InstructionMaker instance with the file hash (MD5).

        Args:
            file_hex_md5 (str): The MD5 hash of the file.
        """
        self.file_hex_md5 = file_hex_md5
        self.instructions = []

    def make_instructions(self):
        """
        Main function to generate instructions based on the pretty dump file.

        This function reads the pretty dump file corresponding to the file hash (MD5) and extracts relevant information
        to generate instructions. The generated instructions are saved to a JSON file.

        Returns:
            self: The InstructionMaker instance.
        """
        pretty_dump_file_path = pathnames['pretty_dump_dir'] / f"{self.file_hex_md5}_pretty_dump.json"
        if pretty_dump_file_path.is_file():
            with open(pretty_dump_file_path, 'r', encoding='utf-8') as file:
                pretty_dump_data = json.load(file)
        else:
            logger.error(f"Pretty dump file {pretty_dump_file_path} not found.")
            return self

        if pretty_dump_data and 'rules' in pretty_dump_data:
            for rule_name, rule_details in pretty_dump_data['rules'].items():
                if 'matches' in rule_details:
                    for match_list in rule_details['matches']:
                        self.instructions.extend(
                            {
                                'Rule Name': rule_name,
                                'Match Type': match.get('type', ''),
                                'Value': match.get('value', 0),
                                'Address': hex(int(match.get('value', 0))),
                                'Instructions': get_instructions_for_address(match.get('value', 0))
                            }
                            for match in match_list
                            if match.get('type') == 'absolute'
                        )

        if not self.instructions:
            logger.error("No instructions to save.")
            return self

        file_path = Path(pathnames['instructions_dir']) / f"{self.file_hex_md5}_instructions.json"
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(self.instructions, f, indent=4, ensure_ascii=False)
        logger.info(f"Instructions have been saved to {file_path}")
        return self