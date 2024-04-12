import os
from datetime import datetime

import ida_lines
import ida_netnode
import idaapi
import idautils
import ida_kernwin

from yaraforge.metadata import pathnames
from .logger import get_global_logger
from ida_lines import GENDSM_REMOVE_TAGS
from pathlib import Path

logger = get_global_logger(pathnames['logger_dir'])


def get_cache_dir():
    """
    Get the cache directory.
    :return: The cache directory.
    """
    logger.info("Getting cache directory.")
    cache_dir = Path(pathnames['cache_dir'])  # Convert string to Path object
    cache_dir.mkdir(parents=True, exist_ok=True)  # This line should now work properly
    return cache_dir


def make_dirs(path_array):
    """
    Make directories for the given paths.
    :param path_array: The paths to make directories for.
    :return: None
    """
    logger.info(f"Making directories for {path_array}.")
    for path in path_array:  # This should be path_array, not pathnames.values()
        try:
            os.makedirs(path, exist_ok=True)
        except PermissionError:
            logger.error(f"Permission denied: Unable to create directory {path}.")
            print(f"Permission denied: Unable to create directory {path}.")
        except Exception as e:
            logger.error(f"Error creating directory {path}: {e}")
            print(f"Error creating directory {path}: {e}")


def get_desktop_path():
    """
    Get the path to the desktop.
    :return: The path to the desktop.
    """
    logger.info("Getting desktop path.")
    desktop_path = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop')
    return desktop_path


def explore_netnodes():
    """
    Explore netnodes to find CAPA netnodes.
    If CAPA netnodes are not found, prompt the user to run CAPA analysis first.
    """
    logger.info("Exploring netnodes.")
    n = ida_netnode.netnode()
    found = False

    if n.start():
        while True:
            name = n.get_name()
            if name and "$ com.mandiant.capa" in name:
                found = True
                logger.info(f"Found CAPA netnode: {name}")
                print(f"Found CAPA netnode: {name}")
            if not n.next():
                if not found:
                    # If no CAPA netnodes are found, inform the user to run CAPA analysis first.
                    logger.error("No CAPA netnodes found. Please run CAPA analysis first.")
                    print("No CAPA netnodes found.")
                    ida_kernwin.warning("No CAPA netnodes found. Please run CAPA analysis first.")
                    raise RuntimeError("No CAPA netnodes found. Please run CAPA analysis first.")
                logger.info("Finished exploring netnodes.")
                print("Finished exploring netnodes.")
                break
    else:
        logger.error("Failed to start netnode exploration.")
        print("Failed to start netnode exploration.")
        ida_kernwin.warning("Failed to start netnode exploration. Please check your IDA setup.")
        raise RuntimeError("Failed to start netnode exploration.")  # Raise an exception if it fails to start


def custom_json_serializer(o):
    """
    Custom JSON serializer for datetime objects.
    :param o: The object to serialize.
    :return: The serialized object.
    """
    if isinstance(o, datetime):
        logger.info("Using custom JSON serializer for datetime object.")
        return o.isoformat()
    logger.error(f"Object of type {o.__class__.__name__} is not JSON serializable.")
    raise TypeError(f"Object of type {o.__class__.__name__} is not JSON serializable.")


def get_instructions_for_address(addr):
    """
    Get the instructions for a given address.
    :param addr:
    :return: A list of instructions.
    """
    instructions = []
    # 確保地址是整數類型
    if isinstance(addr, str):
        addr = int(addr, 16)  # 假設地址是十六進位字符串，轉換為整數
    elif not isinstance(addr, int):
        logger.error(f"Address must be an integer or hex string. Received: {addr}")
        return instructions

    func = idaapi.get_func(addr)
    if func:
        fci = idaapi.FlowChart(func)
        for block in fci:
            if block.start_ea <= addr < block.end_ea:
                for head in idautils.Heads(block.start_ea, block.end_ea):
                    disasm_line = ida_lines.generate_disasm_line(head, GENDSM_REMOVE_TAGS)
                    if disasm_line:
                        instructions.append(f"0x{head:X}: {disasm_line}")
    return instructions
