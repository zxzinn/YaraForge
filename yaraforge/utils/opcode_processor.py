import binascii

from yaraforge.metadata import pathnames
from yaraforge.utils.logger import get_global_logger

logger = get_global_logger(pathnames['logger_dir'])


def format_hex(data):
    """
    Format a hex string by adding spaces between each byte.

    Args:
        data (str): The hex string to format.

    Returns:
        str: The formatted hex string with spaces between each byte.
    """
    return " ".join(data[i:i + 2] for i in range(0, len(data), 2))


def _wildcard_bytes(data, offset, length):
    """
    Replace a range of bytes in a hex string with wildcards ("?").

    Args:
        data (list): The hex string as a list of characters.
        offset (int): The starting offset of the bytes to wildcard.
        length (int): The number of bytes to wildcard.

    Returns:
        list: The modified hex string with the specified bytes replaced by wildcards.
    """
    for i in range(offset, offset + length):
        data[i] = "?"
    return data


def _process_instruction(sig_mode, ins):
    """
    Process an instruction by generating a signature based on the specified signature mode.

    Args:
        sig_mode (str): The signature mode ("loose", "normal", or "strict").
        ins (Instruction): The instruction to process.

    Returns:
        str: The generated signature for the instruction.
    """
    ins_hex_list = list(binascii.hexlify(ins.bytes).decode("ascii").upper())

    if should_wildcard_imm_operand(sig_mode, ins):
        ins_hex_list = _wildcard_bytes(ins_hex_list, ins.imm_offset * 2, ins.imm_size * 2)
    if should_wildcard_disp_operand(sig_mode, ins):
        ins_hex_list = _wildcard_bytes(ins_hex_list, ins.disp_offset * 2, ins.disp_size * 2)

    signature = ''.join(ins_hex_list)
    return signature


def format_bytes_with_space(bytes_str):
    """
    Format a byte string by adding spaces between each byte.

    Args:
        bytes_str (str): The byte string to format.

    Returns:
        str: The formatted byte string with spaces between each byte.
    """
    return ' '.join(bytes_str[i:i + 2] for i in range(0, len(bytes_str), 2))


def should_wildcard_disp_operand(sig_mode, ins):
    """
    Determine whether the displacement operand of an instruction should be wildcarded based on the signature mode.

    Args:
        sig_mode (str): The signature mode ("loose", "normal", or "strict").
        ins (Instruction): The instruction to check.

    Returns:
        bool: True if the displacement operand should be wildcarded, False otherwise.
    """
    if sig_mode in ["loose", "normal"]:
        return True
    else:
        return is_jmp_or_call(ins)


def should_wildcard_imm_operand(sig_mode, ins):
    """
    Determine whether the immediate operand of an instruction should be wildcarded based on the signature mode.

    Args:
        sig_mode (str): The signature mode ("loose", "normal", or "strict").
        ins (Instruction): The instruction to check.

    Returns:
        bool: True if the immediate operand should be wildcarded, False otherwise.
    """
    if sig_mode in ["loose"]:
        return True
    else:
        return is_jmp_or_call(ins)


def is_jmp_or_call(ins):
    """
    Check if an instruction belongs to the "jump" or "call" group.

    Args:
        ins (Instruction): The instruction to check.

    Returns:
        bool: True if the instruction belongs to the "jump" or "call" group, False otherwise.
    """
    for group in ins.groups:
        group_name = ins.group_name(group)
        if group_name in ["jump", "call"]:
            return True
    return False