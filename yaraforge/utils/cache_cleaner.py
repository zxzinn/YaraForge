import shutil

from yaraforge.metadata import pathnames


class CacheCleaner:
    """
    A class to clear the cache directories for a specific MD5 hash.

    This class takes an MD5 hash as input and provides a method to clear the corresponding
    cache directories for YARA rules and merged rules.
    """

    def __init__(self, md5_hash):
        """
        Initialize the CacheCleaner instance with the MD5 hash.

        Args:
            md5_hash (str): The MD5 hash for which the cache needs to be cleared.
        """
        self.md5_hash = md5_hash
        self.yara_rules_dir = pathnames['yara_rules_dir'] / md5_hash
        self.merged_rules_dir = pathnames['merged_rules_dir'] / md5_hash

    def clear_cache(self):
        """
        Clear the cache directories for the specified MD5 hash.

        This method removes the YARA rules directory and the merged rules directory
        associated with the MD5 hash, effectively clearing the cache for that hash.
        If the directories don't exist, no action is taken.
        """
        for dir_path in [self.yara_rules_dir, self.merged_rules_dir]:
            if dir_path.exists():
                shutil.rmtree(dir_path)
                print(f"Cleared cache directory: {dir_path}")