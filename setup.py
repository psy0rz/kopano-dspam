from distutils.core import setup, Extension

setup(name='zarafa-search',
      version='0.1',
      packages=['zarafa_search'],
      package_data={'': ['xmltotext.xslt']},
)
