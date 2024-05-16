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
    def __init__(self, file_hex_md5: str):
        self.file_hex_md5 = file_hex_md5
        self.yara_rules_dir = Path(pathnames['yara_rules_dir'])
        self.merged_rules_dir = Path(pathnames['merged_rules_dir'])

    def merge(self):
        self.yara_rules: List[Dict] = []
        self._scan_rules()
        self._merge_rules()

    def _scan_rules(self):
        """
        掃描指定 MD5 的 YARA 規則檔案,並將它們載入到 self.yara_rules 中。
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
        chunk_dict: Dict[str, List[Dict]] = {}
        for rule in self.yara_rules:
            chunks = self._extract_chunks(rule["content"])
            for chunk in chunks:
                chunk_hash = self._calculate_chunk_hash(chunk)
                if chunk_hash not in chunk_dict:
                    chunk_dict[chunk_hash] = []
                chunk_dict[chunk_hash].append(rule)

        for chunk_hash, rules in chunk_dict.items():
            if len(rules) > 1:
                logger.info(f"Merging {len(rules)} rules for chunk hash: {chunk_hash}")
                merged_rule = self._merge_rule_contents(rules)
                rule_count = len(rules)
                merged_filename = f"{rule_count}_merged_{self._create_rule_name(rules)}.yar"
                self._save_merged_rule(merged_rule, merged_filename)
            else:
                original_filename = Path(rules[0]['file_path']).name
                logger.info(f"No merging required for {original_filename}, saving as is")
                self._save_merged_rule(rules[0]['content'], original_filename)

    def _extract_chunks(self, rule_content: str) -> List[str]:
        """
        使用正則表達式從 YARA 規則中提取所有的 chunk。
        """
        pattern = r'(\$\w+\s*=\s*\{[^\}]*\})'
        return re.findall(pattern, rule_content, re.DOTALL)

    def _calculate_chunk_hash(self, chunk: str) -> str:
        """
        計算 chunk 的 SHA-256 雜湊值。
        """
        return hashlib.sha256(chunk.encode("utf-8")).hexdigest()

    def _merge_rule_contents(self, rules: List[Dict]) -> str:
        if not rules:
            return ""

        generated_by = rules[0]['content'].split('generated_by = ')[1].split('"')[1]
        version = rules[0]['content'].split('version = ')[1].split('"')[1]
        date_str = datetime.now().strftime('%Y-%m-%d %H:%M')
        hash_str = self.file_hex_md5
        rule_name = self._create_rule_name(rules)

        merged_rule = f"rule {rule_name} {{\n"
        merged_rule += "  meta:\n"
        merged_rule += f"    generated_by = \"{generated_by}\"\n"
        merged_rule += f"    date = \"{date_str}\"\n"
        merged_rule += f"    version = \"{version}\"\n"
        merged_rule += f"    hash = \"{hash_str}\"\n"

        # 合併注釋，每個注釋獨立放在自己的註解塊中
        for rule in rules:
            comment = self._extract_comments(rule['content'])
            if comment:
                merged_rule += f"  /*\n\t{comment}\n  */\n"

        # 合併 chunks
        chunks = set(self._extract_chunks(rule['content'])[0] for rule in rules)  # Ensure unique chunks only
        if chunks:
            chunk_block = "\n    ".join(sorted(chunks))
            merged_rule += f"  strings:\n    {chunk_block}\n"
        merged_rule += "  condition:\n    any of them\n}\n"

        return merged_rule

    def _extract_comments(self, rule_content: str) -> str:
        """
        從 YARA 規則中提取注釋部分，不包括註解的開始和結束符號。
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

    def _create_rule_name(self, rules):
        """
        基於所有規則的文件名創建一個新的規則名稱
        """
        names = [Path(rule['file_path']).stem for rule in rules]
        return '_'.join(sorted(set(names)))

    def _save_merged_rule(self, merged_rule: str, file_name: str):
        """
        將合併後的或單一的 YARA 規則保存到檔案中。
        """
        output_dir = self.merged_rules_dir / self.file_hex_md5
        output_dir.mkdir(parents=True, exist_ok=True)
        file_path = output_dir / file_name
        try:
            with open(file_path, "w") as f:
                f.write(merged_rule)
            logger.info(f"Rule saved successfully: {file_path}")
        except Exception as e:
            print(f"Failed to save the rule {file_name} at {output_dir}: {e}")
