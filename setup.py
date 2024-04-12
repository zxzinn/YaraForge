from setuptools import setup, find_packages

from yaraforge.metadata import metadata
from yaraforge.version import get_version

setup(
    name=f"{metadata['plugin_name']}",
    version=f"{get_version()}",
    author=", ".join([author['name'] for author in metadata['authors']]),
    author_email=", ".join([author['email'] for author in metadata['authors']]),
    description=f"{metadata['description']}",
    url=f"{metadata['github_url']}",
    packages=find_packages(),
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Development Status :: 4 - Beta',
    ],
    python_requires='>=3.8, <3.12',  # 這裡設定支持的Python版本為3.8至3.11
    install_requires=[
        'capstone>=5.0.1',
        'flare-capa>=7.0.1',
    ],
    test_suite='yaraforge.tests',
)
