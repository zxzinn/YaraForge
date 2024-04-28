import sys
import requests
import idaapi
from packaging import version

from yaraforge.version import __version__
from yaraforge.utils.logger import get_global_logger

logger = get_global_logger()


def check_for_updates(force_check=False):
    try:
        # 检查网络连接状态
        if not is_network_available():
            if force_check:
                print("[YaraForge] No network connection. Update check skipped.")
            return

        print(f"[YaraForge] Current version: {__version__}")
        logger.info(f"Current version: {__version__}")

        # 从 PyPI 获取最新版本号
        pypi_url = "https://pypi.org/pypi/yaraforge/json"
        response = requests.get(pypi_url)
        response.raise_for_status()
        latest_version_str = response.json()["info"]["version"]

        current_version = version.parse(__version__)
        latest_version = version.parse(latest_version_str)

        if latest_version > current_version:
            print(f"[YaraForge] New version available: {latest_version}")
            logger.info(f"New version available: {latest_version}")
            if idaapi.ask_yn(idaapi.ASKBTN_YES, f"A new version of YaraForge ({latest_version}) is available. Do you "
                                                f"want to update now?") == idaapi.ASKBTN_YES:
                perform_update()
            else:
                print("[YaraForge] You can update later by running the 'yf-update' command in the Python Console.")
        else:
            print("[YaraForge] No updates available.")
            logger.info("No updates available.")
    except requests.exceptions.RequestException as e:
        print(f"[YaraForge] Update check failed: {e}")
        logger.error(f"Update check failed: {e}")


def perform_update():
    try:
        # 直接使用 pip 执行更新
        import subprocess
        subprocess.check_call(["pip", "install", "--upgrade", "yaraforge"])
        print("[YaraForge] Update completed. Please restart IDA Pro for the changes to take effect.")
        logger.info("Update completed. Please restart IDA Pro for the changes to take effect.")
    except subprocess.CalledProcessError as e:
        print("[YaraForge] Update failed. You can still use the current version of YaraForge.")
        print("Please check the IDAPython console for more information.")
        print("You can try updating YaraForge manually by running the following command:")
        print("    pip install --upgrade yaraforge")
        print("Make sure to use the correct Python interpreter associated with your IDA Pro installation.")
        print("If the issue persists, please contact the author or open an issue on GitHub:")
        print("- Author: zhaoxinnZ (zhaoxinzhang0429@gmail.com)")
        print("- GitHub Issues: https://github.com/zhaoxinnZ/YaraForge/issues")
        logger.error(f"Update failed: {e}")
    except Exception as e:
        print(f"[YaraForge] Update failed: {e}")
        print("You can still use the current version of YaraForge.")
        print("Please check the IDAPython console for more information.")
        print("If the issue persists, please contact the author or open an issue on GitHub:")
        print("- Author: zhaoxinnZ (zhaoxinzhang0429@gmail.com)")
        print("- GitHub Issues: https://github.com/zhaoxinnZ/YaraForge/issues")
        logger.error(f"Update failed: {e}")


def is_network_available():
    import socket
    try:
        socket.create_connection(("www.google.com", 80))
        return True
    except OSError:
        return False