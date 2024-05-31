import os
import hashlib
import re
from datetime import datetime
from typing import List, Dict
from pathlib import Path

from yaraforge.metadata import pathnames
from yaraforge.utils.logger import get_global_logger

logger = get_global_logger(pathnames['logger_dir'])


class YaraRuleMerger:
    """
    A class to merge YARA rules based on the file hash (MD5).

    This class takes a file hash (MD5) as input and scans the corresponding YARA rules directory
    for rules related to that file. It then merges the rules based on common chunks (strings)
    and saves the merged rules to a separate directory.
    """

    def __init__(self, file_hex_md5: str):
        """
        Initialize the YaraRuleMerger instance with the file hash (MD5).

        Args:
            file_hex_md5 (str): The MD5 hash of the file.
        """
        self.file_hex_md5 = file_hex_md5
        self.yara_rules_dir = Path(pathnames['yara_rules_dir'])
        self.merged_rules_dir = Path(pathnames['merged_rules_dir'])

    def merge(self):
        """
        Main function to merge the YARA rules.

        This function scans the YARA rules directory for rules related to the file hash,
        merges the rules based on common chunks, and saves the merged rules to a separate directory.
        """
        self.yara_rules: List[Dict] = []
        self._scan_rules()
        self._merge_rules()

    def _scan_rules(self):
        """
        Scan the YARA rules directory for rules related to the file hash.

        This function searches the YARA rules directory for rules specific to the file hash
        and reads the content of each rule file, storing it in the `yara_rules` list.
        """
        rules_dir = self.yara_rules_dir / self.file_hex_md5
        if not rules_dir.exists():
            print(f"No YARA rules found for MD5: {self.file_hex_md5}")
            return

        for file in rules_dir.glob("*.yar"):
            try:
                with open(file, "r") as f:
                    rule_content = f.read()
                    self.yara_rules.append({"file_path": str(file), "content": rule_content})
            except IOError as e:
                print(f"Error reading file {file}: {e}")

    def _merge_rules(self):
        """
        Merge the YARA rules based on common chunks.

        This function extracts chunks (strings) from each rule, calculates their hash,
        and groups the rules with the same chunk hash together. It then merges the rules
        within each group and saves the merged rules to a separate directory.
        """
        chunk_dict: Dict[str, List[Dict]] = {}
        for rule in self.yara_rules:
            chunks = self._extract_chunks(rule["content"])
            for chunk in chunks:
                chunk_hash = self._calculate_chunk_hash(chunk)
                if chunk_hash not in chunk_dict:
                    chunk_dict[chunk_hash] = []
                chunk_dict[chunk_hash].append(rule)

        rule_index = 1
        for chunk_hash, rules in chunk_dict.items():
            rule_count = len(rules)
            if rule_count > 1:
                logger.info(f"Merging {rule_count} rules for chunk hash: {chunk_hash}")
                merged_rule = self._merge_rule_contents(rules, chunk_dict[chunk_hash][0]['content'], rule_index)
                chunk_strings_count = self._count_strings_in_chunk(chunk_dict[chunk_hash][0]['content'])
                if chunk_strings_count > 8000:
                    logger.warning(
                        f"Skipping rule with {chunk_strings_count} strings: {self._create_rule_name(rules, chunk_dict[chunk_hash][0]['content'], rule_index)}")
                    continue
                merged_filename = self._create_rule_name(rules, chunk_dict[chunk_hash][0]['content'],
                                                         rule_index) + ".yar"
                self._save_merged_rule(merged_rule, merged_filename)
                rule_index += 1
            else:
                original_filename = Path(rules[0]['file_path']).name
                chunk_strings_count = self._count_strings_in_chunk(rules[0]['content'])
                if chunk_strings_count > 8000:
                    logger.warning(f"Skipping rule with {chunk_strings_count} strings: {original_filename}")
                    continue
                logger.info(f"No merging required for {original_filename}, saving as is")
                original_filename_without_ext = original_filename.split('.')[0]
                new_filename = f"{original_filename_without_ext}_{chunk_strings_count}.yar"
                self._save_merged_rule(rules[0]['content'], new_filename)

    def _extract_chunks(self, rule_content: str) -> List[str]:
        """
        Extract chunks (strings) from the YARA rule content.

        Args:
            rule_content (str): The content of the YARA rule.

        Returns:
            List[str]: A list of chunks (strings) extracted from the rule content.
        """
        pattern = r'(\$\w+\s*=\s*\{[^\}]*\})'
        return re.findall(pattern, rule_content, re.DOTALL)

    def _calculate_chunk_hash(self, chunk: str) -> str:
        """
        Calculate the hash of a chunk (string).

        Args:
            chunk (str): The chunk (string) to calculate the hash for.

        Returns:
            str: The SHA-256 hash of the chunk.
        """
        return hashlib.sha256(chunk.encode("utf-8")).hexdigest()

    def _merge_rule_contents(self, rules: List[Dict], chunk: str, rule_index: int) -> str:
        """
        Merge the contents of multiple YARA rules into a single rule.

        Args:
            rules (List[Dict]): A list of dictionaries representing the YARA rules to merge.
            chunk (str): The common chunk (string) shared by the rules.
            rule_index (int): The index of the merged rule.

        Returns:
            str: The merged YARA rule content.
        """
        if not rules:
            return ""

        generated_by = rules[0]['content'].split('generated_by = ')[1].split('"')[1]
        version = rules[0]['content'].split('version = ')[1].split('"')[1]
        date_str = datetime.now().strftime('%Y-%m-%d %H:%M')
        hash_str = self.file_hex_md5

        merged_rule_name = self._create_rule_name(rules, chunk, rule_index)

        merged_rule = f"rule {merged_rule_name} {{\n"
        merged_rule += "  meta:\n"
        merged_rule += f"    generated_by = \"{generated_by}\"\n"
        merged_rule += f"    date = \"{date_str}\"\n"
        merged_rule += f"    version = \"{version}\"\n"
        merged_rule += f"    hash = \"{hash_str}\"\n"

        rule_index = 1
        for rule in rules:
            rule_path = rule['file_path']
            rule_address = rule_path.split('\\')[-1].split('.')[0]
            rule_name = f"rule_{rule_index} = \"{rule_address}\""
            merged_rule += f"\n\t{rule_name}\n"
            comment = self._extract_comments(rule['content'])
            if comment:
                merged_rule += f"  /*\n{comment}\n  */\n"
            rule_index += 1

        chunks = set(self._extract_chunks(rule['content'])[0] for rule in rules)
        if chunks:
            chunk_block = "\n    ".join(sorted(chunks))
            merged_rule += f"  strings:\n    {chunk_block}\n"
        merged_rule += "  condition:\n    any of them\n}\n"

        return merged_rule

    def _extract_comments(self, rule_content: str) -> str:
        """
        Extract comments from the YARA rule content.

        Args:
            rule_content (str): The content of the YARA rule.

        Returns:
            str: The extracted comments from the rule content.
        """
        comments = []
        lines = rule_content.split("\n")
        in_comment = False
        for line in lines:
            line = line.strip()
            if line.startswith("/*"):
                in_comment = True
                continue  # Skip the comment start marker
            elif line.endswith("*/"):
                in_comment = False
                continue  # Skip the comment end marker
            if in_comment:
                comments.append("\t" + line)  # Maintain a tab for better formatting
        return "\n".join(comments)

    def _create_rule_name(self, rules, chunk, rule_index):
        """
        Create a name for the merged YARA rule.

        Args:
            rules (List[Dict]): A list of dictionaries representing the YARA rules to merge.
            chunk (str): The common chunk (string) shared by the rules.
            rule_index (int): The index of the merged rule.

        Returns:
            str: The name of the merged YARA rule.
        """
        rule_count = len(rules)
        chunk_strings_count = self._count_strings_in_chunk(chunk)

        return f"Merged_Rule_{rule_index}_{rule_count}times_{chunk_strings_count}"

    def _count_strings_in_chunk(self, chunk):
        """
        Count the number of strings in a chunk (string).

        Args:
            chunk (str): The chunk (string) to count the strings in.

        Returns:
            int: The number of strings in the chunk.
        """
        count = 0
        for line in chunk.split('\n'):
            line = line.strip()
            if line and not line.endswith('??'):
                hex_strings = re.findall(r'[0-9A-Fa-f]{2,}', line)
                count += len(hex_strings)
        return count

    def _save_merged_rule(self, rule_content: str, filename: str):
        """
        Save the merged YARA rule to a file.

        Args:
            rule_content (str): The content of the merged YARA rule.
            filename (str): The name of the file to save the merged rule to.
        """
        output_dir = self.merged_rules_dir / self.file_hex_md5
        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = output_dir / filename
        try:
            with open(output_file, "w") as f:
                f.write(rule_content)
            logger.info(f"Saved merged rule to {output_file}")
        except IOError as e:
            logger.error(f"Error writing merged rule to {output_file}: {e}")