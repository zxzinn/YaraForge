import json
from datetime import datetime
from pathlib import Path
from ida_lines import GENDSM_REMOVE_TAGS

import ida_lines
import idaapi
import idc
from capstone import *

from yaraforge.metadata import metadata
from yaraforge.version import get_version
from ..utils.opcode_processor import *
from ..utils.opcode_processor import _process_instruction

logger = get_global_logger(pathnames['logger_dir'])


class YaraMaker:
    def __init__(self, file_hex_md5):
        """
        Initialize the YaraMaker object.
        :param file_hex_md5: The MD5 hash of the file.
        :return: None
        """
        self.file_hex_md5 = file_hex_md5
        self.sig_mode = "normal"
        self.strings = []
        self.comments = []
        self.metas = {
            "generated_by": f"{metadata['plugin_name']} v{get_version()}",
            "date": "\"{}\"".format(datetime.now().strftime("%Y-%m-%d %H:%M")),
            "version": f"{get_version()}",
            "hash": f"{file_hex_md5}",
        }
        self.output_dir = Path(pathnames['yara_rules_dir']) / file_hex_md5
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.instructions_info = []

    def generate_rule(self):
        """
        Generate YARA rules for the file.
        :return: None
        """
        instructions_path = Path(pathnames['instructions_dir']) / f"{self.file_hex_md5}_instructions.json"

        with open(instructions_path, 'r', encoding='utf-8') as file:
            data = json.load(file)

        for rule in data:
            address = int(rule.get("Address"), 16)
            rule_name = rule.get("Rule Name", f"generated_rule_{hex(address)}").replace(' ', '_').replace('-', '_')

            self.strings = []  # Reset strings list for each rule
            self.comments = []  # Reset comments list for each rule
            self.instructions_info = []  # Reset instructions_info list for each rule
            all_instructions_signature = []
            func = idaapi.get_func(address)
            if not func:
                print(f"Address {hex(address)} does not belong to any function.")
                continue

            # 取得目前的架構
            info = idaapi.get_inf_structure()
            if info.is_64bit():
                md = Cs(CS_ARCH_X86, CS_MODE_64)
            elif info.is_32bit():
                md = Cs(CS_ARCH_X86, CS_MODE_32)
            else:
                print("Unsupported architecture.")
                continue

            md.detail = True

            fci = idaapi.FlowChart(func)
            for block in fci:
                if block.start_ea <= address < block.end_ea:
                    code_bytes = idc.get_bytes(block.start_ea, block.end_ea - block.start_ea)
                    disasm = md.disasm(code_bytes, block.start_ea)
                    for ins in disasm:
                        signature = _process_instruction(ins)
                        formatted_signature = format_hex(signature)
                        all_instructions_signature.append(formatted_signature)
                        bytes_formatted = format_bytes_with_space(ins.bytes.hex().upper())
                        instruction_detail = {
                            'address': ins.address,
                            'mnemonic': ins.mnemonic,
                            'op_str': ins.op_str,
                            'bytes': bytes_formatted
                        }
                        self.instructions_info.append(instruction_detail)

            yara_path = Path(pathnames['yara_rules_dir']) / f"{self.file_hex_md5}"
            if all_instructions_signature:
                signature_str = "\n\t\t\t".join(all_instructions_signature)
                self.print_rule(rule_name, address, signature_str)
        print(f"YARA rules has been saved to {yara_path}")

    def print_rule(self, rule_name, address, signature_str):
        """
        Print the YARA rule to a file.
        :param rule_name:
        :param address:
        :param signature_str:
        :return:
        """
        formatted_rule_name = f"{rule_name}_{hex(address)}"
        rule_comments = "\n\t/*\n\t" + "\n\t".join([
            f"{hex(ins['address'])}:\t{ins['bytes'].ljust(40)} ; {ida_lines.generate_disasm_line(ins['address'], GENDSM_REMOVE_TAGS)}"
            for ins in self.instructions_info
        ]) + "\n\t*/\n"

        rule_content = f"rule {formatted_rule_name} {{\n"
        rule_content += "  meta:\n"
        for key, value in self.metas.items():
            # 檢查 value 是否已經是一個字符串，如果是，則在其前後添加引號
            if isinstance(value, str) and not value.startswith("\""):
                value = f"\"{value}\""
            rule_content += f"    {key} = {value}\n"
        rule_content += rule_comments
        rule_content += "  strings:\n"
        rule_content += f"    $chunk_1 = {{\n\t\t\t{signature_str}\n\t\t}}\n"
        rule_content += "  condition:\n    any of them\n}\n"

        yara_rule_path = self.output_dir / f"{formatted_rule_name}.yar"
        with open(yara_rule_path, 'w', encoding='utf-8') as file:
            file.write(rule_content)
        logger.info(f"YARA rule for {formatted_rule_name} has been saved to {yara_rule_path}")





