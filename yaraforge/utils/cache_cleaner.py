import shutil

from yaraforge.metadata import pathnames


class CacheCleaner:
    """
    用于清理与特定 MD5 哈希相关的缓存目录。
    """
    def __init__(self, md5_hash):
        """
        初始化 CacheCleaner。
        :param md5_hash: 要清理的文件的 MD5 哈希。
        """
        self.md5_hash = md5_hash
        # 拉取全局的路径配置
        self.yara_rules_dir = pathnames['yara_rules_dir'] / md5_hash
        self.merged_rules_dir = pathnames['merged_rules_dir'] / md5_hash

    def clear_cache(self):
        """
        清除与给定 MD5 哈希相关的所有缓存目录。
        """
        for dir_path in [self.yara_rules_dir, self.merged_rules_dir]:
            if dir_path.exists():
                shutil.rmtree(dir_path)
                print(f"Cleared cache directory: {dir_path}")
