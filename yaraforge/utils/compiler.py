import subprocess
from pathlib import Path
import platform
import os
import ida_kernwin

from yaraforge.metadata import pathnames


class YaraCompiler:
    """
    A class to compile YARA rules using the yarac compiler.

    This class takes a file hash (MD5) as input and provides methods to determine the appropriate yarac compiler path,
    prompt the user to compile the YARA rules, and perform the actual compilation of the rules.
    """

    def __init__(self, file_hex_md5):
        """
        Initialize the YaraCompiler instance with the file hash (MD5).

        Args:
            file_hex_md5 (str): The MD5 hash of the file.
        """
        self.file_hex_md5 = file_hex_md5
        self.merged_rules_dir = Path(pathnames['merged_rules_dir']) / file_hex_md5
        self.compiled_rules_dir = Path(pathnames['compiled_rules_dir'])
        self.compiled_rules_dir.mkdir(parents=True, exist_ok=True)
        self.yarac_path = self.determine_yarac_path()

    def determine_yarac_path(self):
        """
        Determine the appropriate yarac compiler path based on the system architecture.

        Returns:
            Path: The path to the yarac compiler executable.
        """
        base_path = Path(__file__).resolve().parent.parent / "yarac"
        arch = platform.architecture()[0]
        if '64' in arch:
            return base_path / "yarac64.exe"
        else:
            return base_path / "yarac32.exe"

    def ask_for_compiler(self):
        """
        Prompt the user to compile the YARA rules.

        This method asks the user if they want to compile the YARA rules now. If the user selects "Yes",
        it calls the `compile_rules()` method to perform the compilation. If the user selects "No",
        it prints a message indicating that the compilation was aborted by the user.
        """
        title = "Compile YARA Rules"
        question = "Do you want to compile the YARA rules now?"
        if ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, f"{question}\n\n{title}") == ida_kernwin.ASKBTN_YES:
            self.compile_rules()
        else:
            print("Compilation aborted by the user.")

    def compile_rules(self):
        """
        Compile the YARA rules using the yarac compiler.

        This method merges the YARA rule files into a single file, saves it to the merged rules directory,
        and then compiles the merged file using the yarac compiler. The compiled rules are saved to the
        compiled rules directory. If the compilation is successful, it prints a success message. If the
        compilation fails, it prints an error message with the compilation error.
        """
        merged_content = ''
        rule_files = list(self.merged_rules_dir.glob("*.yar"))
        if not rule_files:
            print("No YARA rules found to compile.")
            return

        for rule_file in rule_files:
            with open(rule_file, 'r', encoding='utf-8') as file:
                merged_content += file.read() + '\n\n'

        merged_file_path = self.merged_rules_dir / f"{self.file_hex_md5}.yar"
        with open(merged_file_path, 'w', encoding='utf-8') as merged_file:
            merged_file.write(merged_content)

        output_file = self.compiled_rules_dir / f"{self.file_hex_md5}.cbin"
        ps_command = f'& "{self.yarac_path}" "{merged_file_path}" "{output_file}"'
        command = ['powershell', '-Command', ps_command]

        try:
            subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            print(f"Successfully compiled: {output_file}")
        except subprocess.CalledProcessError as e:
            print(f"Failed to compile {merged_file_path}: {e.stderr}")