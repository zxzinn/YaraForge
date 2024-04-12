import json
from pathlib import Path

from yaraforge.metadata import pathnames
from yaraforge.utils.common import get_instructions_for_address
from yaraforge.utils.logger import get_global_logger

logger = get_global_logger(pathnames['logger_dir'])


class InstructionMaker:
    def __init__(self, file_hex_md5):
        """
        Initialize the InstructionMaker object.
        :param file_hex_md5: The MD5 hash of the file.
        :return: None
        """
        self.file_hex_md5 = file_hex_md5
        self.instructions = []

    def make_instructions(self):
        """
        Make instructions for the file.

        :return: None
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
                        for match in match_list:
                            if match.get('type') == 'absolute':
                                match_value = match.get('value', 0)
                                match_value_hex = hex(int(match_value)) if match_value else '0x0'
                                instructions = get_instructions_for_address(match_value)
                                self.instructions.append({
                                    'Rule Name': rule_name,
                                    'Match Type': match.get('type', ''),
                                    'Value': match_value,
                                    'Address': match_value_hex,
                                    'Instructions': instructions
                                })

        # 在函數末尾加上保存指令的邏輯
        if not self.instructions:
            logger.error("No instructions to save.")
            return

        file_path = Path(pathnames['instructions_dir']) / f"{self.file_hex_md5}_instructions.json"
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(self.instructions, f, indent=4, ensure_ascii=False)
        logger.info(f"Instructions has been saved to {file_path}")
        return self

