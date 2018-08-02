from distutils.core import setup, Extension

setup(name='kopano-dspam',
      version='0.1',
      packages=['kopano_dspam'],
      package_data={'': ['xmltotext.xslt']},
)
