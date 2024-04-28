import binascii
import idaapi
import idautils

from ..updater.update import check_for_updates
from ..utils.cache_dumper import DumpAsker
from ..utils.common import *
from yaraforge.maker.dump_maker import *
from yaraforge.maker.instruction_maker import InstructionMaker
from ..utils.logger import *
from ..utils.logger import get_global_logger
from yaraforge.maker.yara_maker import YaraMaker

logger = get_global_logger(pathnames['logger_dir'])


class YaraForgePlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "YaraForge Plugin for IDA Pro Integrated with CAPA and mkYARA."
    help = "YaraForge Plugin"
    wanted_name = "YaraForge"
    wanted_hotkey = "Alt-Y"

    def init(self):
        try:
            initialize_logger()
            logger.info("YaraForge plugin initialized")
            print(f"{metadata['plugin_name']} plugin initialized")
            check_for_updates()
        except Exception as e:
            print(f"Error: Exception occurred during logger initialization, reason: {e}")
        return idaapi.PLUGIN_OK

    def term(self):
        try:
            logger.info("YaraForge plugin terminated")
            print(f"{metadata['plugin_name']} plugin terminated")
        except Exception as e:
            print(f"Error: Exception occurred during plugin termination, reason: {e}")

    def run(self, arg):
        try:
            logger.info("YaraForge plugin run started")

            file_hex_md5 = binascii.hexlify(idautils.GetInputFileMD5()).decode('ascii').lower()

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

            asker = DumpAsker()
            asker.ask_user_for_dump()



        except Exception as e:
            logger.error(f"Error occurred during YaraForge plugin execution: {e}")
            print(f"Error occurred during YaraForge plugin execution: {e}")


def PLUGIN_ENTRY():
    return YaraForgePlugin()
