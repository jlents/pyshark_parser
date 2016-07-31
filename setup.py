from setuptools import setup

setup(name='pyshark_parser',
      version='0.1',
      description='A library for parsing pyshark pcap objects',
      url='http://github.com/jlents/pyshark_parser',
      author='Joshua Lents',
      author_email='joshua.lents@gmail.com',
      license='MIT',
      packages=['pyshark_parser'],
      install_requires=[
          'pyshark',
      ],
      zip_safe=False)
