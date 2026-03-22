from setuptools import setup

setup(
    name='vibescan',
    version='1.0.0',
    description='An Asyncio-powered specialist port scanner with OS inference and vulnerability matching.',
    py_modules=['vibescan'],
    install_requires=[
        'rich',
    ],
    entry_points={
        'console_scripts': [
            'vibescan=vibescan:cli_main',
        ],
    },
)
