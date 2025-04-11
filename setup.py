from setuptools import setup, find_packages

setup(
    name="cbom-detector",
    version="1.0.0",
    description="Cryptographic Bill of Materials Scanner and Quantum Risk Assessment Tool",
    author="CBOM Team",
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'cbom-detector=cbom_detector.detector:main',
        ],
    },
    install_requires=[
        'colorama',
        'cryptography',
        'requests',
        'rich',
    ],
    python_requires='>=3.6',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Topic :: Security :: Cryptography',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
    ],
)