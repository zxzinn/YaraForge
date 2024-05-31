from pathlib import Path

import ida_kernwin
import shutil
import os

from yaraforge.metadata import pathnames
from yaraforge.utils.common import get_desktop_path
from yaraforge.utils.logger import get_global_logger

logger = get_global_logger(pathnames['logger_dir'])


class DumpAsker:
    """
    A class to prompt the user to dump the YaraForge cache directory to the desktop.

    This class provides a method to ask the user if they want to dump the YaraForge cache directory
    to the desktop. If the user agrees, it copies the cache directory to the desktop.
    """

    def __init__(self):
        """
        Initialize the DumpAsker instance.

        This method sets up the paths for the YaraForge cache directory and the desktop directory.
        """
        self.yaraforge_dir_path = Path(pathnames['yaraforge_dir'])
        self.desktop_path = get_desktop_path()

    def ask_user_for_dump(self):
        """
        Ask the user if they want to dump the YaraForge cache directory to the desktop.

        This method prompts the user with a dialog asking if they want to dump the YaraForge cache
        directory to the desktop. If the user selects "Yes", it copies the cache directory to the
        desktop. If the user selects "No", it prints a message indicating that the user chose not
        to dump the caches.
        """
        answer = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, "Dump Caches on desktop?")
        if answer == ida_kernwin.ASKBTN_YES:
            target_path = os.path.join(self.desktop_path, os.path.basename(self.yaraforge_dir_path))
            try:
                if os.path.exists(target_path):
                    shutil.rmtree(target_path)
                shutil.copytree(self.yaraforge_dir_path, target_path)
                print(f"Cache directory successfully copied to {target_path}")
            except Exception as e:
                print(f"Error copying cache directory: {e}")
        else:
            print("User chose not to dump caches.")