import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="wiretap",
    version="0.3.1-alpha",
    description="Agentless health and log aggregation for unix systems",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
    ],
    python_requires='>=3.8',
    install_requires=[
        'influxdb_client',
        'pydantic',
        'requests',
        'parallel-ssh',
    ]
)
