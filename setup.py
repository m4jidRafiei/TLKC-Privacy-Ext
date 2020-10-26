import setuptools

import p_tlkc_privacy

with open("README.md", "r") as fh:
    long_description = fh.read()


setuptools.setup(
    name=p_tlkc_privacy.__name__,
    version=p_tlkc_privacy.__version__,
    author=p_tlkc_privacy.__author__,
    author_email=p_tlkc_privacy.__author_email__,
    description="TLKC-privacy model for process mining",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/m4jidRafiei/TLKC-Privacy",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        'pm4py==1.2.10',
        'typing==3.6.4',
        'setuptools==41.0.1',
        'mlxtend==0.14.0',
        'pyfpgrowth==1.0',
        'pandas==0.24.2',
        'numpy==1.18.1',
        'p_privacy_metadata==0.0.4'
    ],
    project_urls={
        'Source': 'https://github.com/m4jidRafiei/TLKC-Privacy'
    }
)

