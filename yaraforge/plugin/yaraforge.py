# main.py
from yaraforge.plugin import YaraForgePlugin


def PLUGIN_ENTRY():

    """mandatory entry point for IDAPython plugins.

    copy this script to your IDA plugins directory and start the plugin by navigating to Edit > Plugins in IDA Pro
    """
    return YaraForgePlugin()
