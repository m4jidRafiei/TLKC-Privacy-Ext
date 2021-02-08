import setuptools

import p_tlkc_privacy_ext

with open("README.md", "r") as fh:
    long_description = fh.read()


setuptools.setup(
    name=p_tlkc_privacy_ext.__name__,
    version=p_tlkc_privacy_ext.__version__,
    author=p_tlkc_privacy_ext.__author__,
    author_email=p_tlkc_privacy_ext.__author_email__,
    description="TLKC-privacy model for process mining",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/m4jidRafiei/TLKC-Privacy-Ext",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        'pyfpgrowth == 1.0',
        'multiset == 2.1.1',
        'pm4py == 1.2.10',
        'numpy >= 1.18.1',
        'p_privacy_metadata == 0.0.4',
        'pandas >= 0.24.2',
        'mlxtend == 0.14.0',
        'python_dateutil>=2.8.1'
    ],
    project_urls={
        'Source': 'https://github.com/m4jidRafiei/TLKC-Privacy-Ext'
    }
)

