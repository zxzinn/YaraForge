import binascii
import idaapi
import idautils

from ..updater.update import check_for_updates
from ..utils.cache_cleaner import CacheCleaner
from ..utils.cache_dumper import DumpAsker
from ..utils.common import *
from yaraforge.maker.dump_maker import *
from yaraforge.maker.instruction_maker import InstructionMaker
from ..utils.compiler import YaraCompiler
from ..utils.logger import *
from ..utils.logger import get_global_logger
from yaraforge.maker.yara_maker import YaraMaker
from yaraforge.maker.merge_maker import YaraRuleMerger

logger = get_global_logger(pathnames['logger_dir'])


class YaraForgePlugin(idaapi.plugin_t):
    """
    The main plugin class for YaraForge.

    This class defines the plugin's behavior, including initialization, termination, and execution.
    It orchestrates the various components of YaraForge, such as cache cleaning, pretty dumping,
    instruction generation, YARA rule generation, and YARA rule merging.
    """

    flags = idaapi.PLUGIN_UNL
    comment = "YaraForge Plugin for IDA Pro Integrated with CAPA and mkYARA."
    help = "YaraForge Plugin"
    wanted_name = "YaraForge"
    wanted_hotkey = "Alt-Y"

    def init(self):
        """
        Initialize the YaraForge plugin.

        This method is called when the plugin is loaded. It initializes the logger,
        checks for updates, and prints a message indicating that the plugin has been initialized.

        Returns:
            int: Always returns idaapi.PLUGIN_OK to indicate successful initialization.
        """
        try:
            initialize_logger()
            logger.info("YaraForge plugin initialized")
            print(f"{metadata['plugin_name']} plugin initialized")
            check_for_updates()
        except Exception as e:
            print(f"Error: Exception occurred during logger initialization, reason: {e}")
        return idaapi.PLUGIN_OK

    def term(self):
        """
        Terminate the YaraForge plugin.

        This method is called when the plugin is unloaded. It logs a message indicating
        that the plugin has been terminated.
        """
        try:
            logger.info("YaraForge plugin terminated")
            print(f"{metadata['plugin_name']} plugin terminated")
        except Exception as e:
            print(f"Error: Exception occurred during plugin termination, reason: {e}")

    def run(self, arg):
        """
        Run the YaraForge plugin.

        This method is called when the plugin is executed. It performs the main functionality
        of YaraForge, including cache cleaning, pretty dumping, instruction generation,
        YARA rule generation, and YARA rule merging.

        Args:
            arg: Unused argument passed by IDA Pro.
        """
        try:
            logger.info("YaraForge plugin run started")

            file_hex_md5 = binascii.hexlify(idautils.GetInputFileMD5()).decode('ascii').lower()

            cache_cleaner = CacheCleaner(file_hex_md5)
            cache_cleaner.clear_cache()

            # Explore Netnodes
            explore_netnodes()

            # Make Directories
            make_dirs(pathnames.values())

            # Pretty Dump
            dump = DumpMaker(file_hex_md5)
            dump.make_pretty_dump()

            # Instruction Data
            inst = InstructionMaker(file_hex_md5)
            inst.make_instructions()

            # Yara Rule Generation
            yara = YaraMaker(file_hex_md5)
            yara.generate_rule()

            # Merge Yara Rules
            merger = YaraRuleMerger(file_hex_md5)
            merger.merge()

            yarac = YaraCompiler(file_hex_md5)
            yarac.ask_for_compiler()

            asker = DumpAsker()
            asker.ask_user_for_dump()

        except Exception as e:
            logger.error(f"Error occurred during YaraForge plugin execution: {e}")
            print(f"Error occurred during YaraForge plugin execution: {e}")


def PLUGIN_ENTRY():
    """
    Entry point for the YaraForge plugin.

    This function is called by IDA Pro to create an instance of the YaraForgePlugin class.

    Returns:
        YaraForgePlugin: An instance of the YaraForgePlugin class.
    """
    return YaraForgePlugin()