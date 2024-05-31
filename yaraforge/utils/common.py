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
    Get the cache directory path and create it if it doesn't exist.

    Returns:
        Path: The cache directory path.
    """
    logger.info("Getting cache directory.")
    cache_dir = Path(pathnames['cache_dir'])  # Convert string to Path object
    cache_dir.mkdir(parents=True, exist_ok=True)  # This line should now work properly
    return cache_dir


def make_dirs(path_array):
    """
    Create directories specified in the path_array.

    Args:
        path_array (list): A list of directory paths to create.
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
    Get the desktop path of the current user.

    Returns:
        str: The desktop path.
    """
    logger.info("Getting desktop path.")
    desktop_path = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop')
    return desktop_path


def explore_netnodes():
    """
    Explore netnodes and check for the presence of CAPA netnodes.

    Raises:
        RuntimeError: If no CAPA netnodes are found or if it fails to start netnode exploration.
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

    Args:
        o: The object to serialize.

    Returns:
        str: The serialized representation of the object.

    Raises:
        TypeError: If the object is not JSON serializable.
    """
    if isinstance(o, datetime):
        logger.info("Using custom JSON serializer for datetime object.")
        return o.isoformat()
    logger.error(f"Object of type {o.__class__.__name__} is not JSON serializable.")
    raise TypeError(f"Object of type {o.__class__.__name__} is not JSON serializable.")


def get_instructions_for_address(addr):
    """
    Get the instructions for a given address.

    Args:
        addr (int or str): The address to get instructions for. Can be an integer or a hex string.

    Returns:
        list: A list of instructions in the format "0x<address>: <disassembly>".
    """
    instructions = []
    if isinstance(addr, str):
        addr = int(addr, 16)
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