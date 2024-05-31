import json
import os
import shutil
from datetime import datetime
from pathlib import Path
from ida_lines import GENDSM_REMOVE_TAGS

import ida_lines
import idaapi
import idc
import ida_kernwin
from capstone import *

from yaraforge.metadata import metadata
from yaraforge.version import get_version
from ..utils.opcode_processor import *
from ..utils.opcode_processor import _process_instruction

logger = get_global_logger(pathnames['logger_dir'])


class YaraMaker:
    """
    A class to generate YARA rules based on the instructions of a given file.

    This class takes a file hash (MD5) as input and generates YARA rules for the instructions
    associated with that file. It uses the Capstone disassembly library to process the instructions
    and generates YARA rules based on the selected signature mode (normal or loose).
    """

    def __init__(self, file_hex_md5):
        """
        Initialize the YaraMaker instance with the file hash (MD5).

        Args:
            file_hex_md5 (str): The MD5 hash of the file.
        """
        self.file_hex_md5 = file_hex_md5
        self.sig_mode = self.ask_user_for_signature_mode()
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
        Main function to generate YARA rules based on the instructions.

        This function reads the instructions from a JSON file, processes each instruction
        using the selected signature mode, and generates YARA rules for each relevant block
        of instructions. The generated YARA rules are saved to individual files in the output directory.
        """
        instructions_path = Path(pathnames['instructions_dir']) / f"{self.file_hex_md5}_instructions.json"

        with open(instructions_path, 'r', encoding='utf-8') as file:
            data = json.load(file)

        for rule in data:
            address = int(rule.get("Address"), 16)
            rule_name = rule.get("Rule Name", f"generated_rule_{hex(address)}").replace(' ', '_').replace('-', '_')

            self.strings = []
            self.comments = []
            self.instructions_info = []
            all_instructions_signature = []
            func = idaapi.get_func(address)
            if not func:
                print(f"Address {hex(address)} does not belong to any function.")
                continue

            # Get the architecture mode
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
                        signature = _process_instruction(self.sig_mode, ins)
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
        print(f"YARA rules have been saved to {yara_path}")

    def print_rule(self, rule_name, address, signature_str):
        """
        Generate and save the YARA rule to a file.

        Args:
            rule_name (str): The name of the YARA rule.
            address (int): The address associated with the YARA rule.
            signature_str (str): The string representation of the YARA rule signature.
        """
        formatted_rule_name = f"{rule_name}_{hex(address)}"
        rule_comments = "\n\t/*\n\t" + "\n\t".join([
            f"{hex(ins['address'])}:\t{ins['bytes'].ljust(40)} ; {sanitize_comment(ida_lines.generate_disasm_line(ins['address'], GENDSM_REMOVE_TAGS))}"
            for ins in self.instructions_info
        ]) + "\n\t*/\n"

        rule_content = f"rule {formatted_rule_name} {{\n"
        rule_content += "  meta:\n"
        for key, value in self.metas.items():
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

    def ask_user_for_signature_mode(self):
        """
        Ask the user to select the signature mode (normal or loose).

        Returns:
            str: The selected signature mode ("normal" or "loose").
        """
        title = "Select Signature Mode"
        result = ida_kernwin.ask_buttons("Normal", "Loose", "Cancel", 0, title)

        if result == 0:  # Loose
            return "loose"
        elif result == 1:  # Normal
            return "normal"
        return "normal"  # Default or if Cancelled


def sanitize_comment(comment):
    """
    Sanitize the comment by replacing special characters.

    Args:
        comment (str): The comment to sanitize.

    Returns:
        str: The sanitized comment.
    """
    return comment.replace("*/", "(* /)").replace("/*", "(/ *)")