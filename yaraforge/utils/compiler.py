import subprocess
from pathlib import Path
import platform
import os
import ida_kernwin

from yaraforge.metadata import pathnames


class YaraCompiler:
    def __init__(self, file_hex_md5):
        self.file_hex_md5 = file_hex_md5
        self.merged_rules_dir = Path(pathnames['merged_rules_dir']) / file_hex_md5
        self.compiled_rules_dir = Path(pathnames['compiled_rules_dir'])
        self.compiled_rules_dir.mkdir(parents=True, exist_ok=True)
        self.yarac_path = self.determine_yarac_path()

    def determine_yarac_path(self):
        base_path = Path(__file__).resolve().parent.parent / "yarac"
        arch = platform.architecture()[0]
        if '64' in arch:
            return base_path / "yarac64.exe"
        else:
            return base_path / "yarac32.exe"

    def ask_for_compiler(self):
        title = "Compile YARA Rules"
        question = "Do you want to compile the YARA rules now?"
        if ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, f"{question}\n\n{title}") == ida_kernwin.ASKBTN_YES:
            self.compile_rules()
        else:
            print("Compilation aborted by the user.")

    def compile_rules(self):
        # 合并所有的 .yar 文件
        merged_content = ''
        rule_files = list(self.merged_rules_dir.glob("*.yar"))
        if not rule_files:
            print("No YARA rules found to compile.")
            return

        for rule_file in rule_files:
            with open(rule_file, 'r', encoding='utf-8') as file:
                merged_content += file.read() + '\n\n'

        # 使用传入的 MD5 作为文件名
        merged_file_path = self.merged_rules_dir / f"{self.file_hex_md5}.yar"
        with open(merged_file_path, 'w', encoding='utf-8') as merged_file:
            merged_file.write(merged_content)

        # 编译合并后的文件
        output_file = self.compiled_rules_dir / f"{self.file_hex_md5}.cbin"
        ps_command = f'& "{self.yarac_path}" "{merged_file_path}" "{output_file}"'
        command = ['powershell', '-Command', ps_command]

        try:
            subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            print(f"Successfully compiled: {output_file}")
        except subprocess.CalledProcessError as e:
            print(f"Failed to compile {merged_file_path}: {e.stderr}")

