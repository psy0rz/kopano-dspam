from distutils.core import setup, Extension

setup(name='zarafa-spamd',
      version='0.1',
      packages=['zarafa_spamd'],
      package_data={'': ['xmltotext.xslt']},
)
