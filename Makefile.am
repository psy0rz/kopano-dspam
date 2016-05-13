dist_sbin_SCRIPTS = zarafa-search zarafa-search-xapian-compact.py

EXTRA_DIST = setup.py		\
	zarafa_search/__init__.py \
	zarafa_search/plaintext.py \
	zarafa_search/magic.py \
	zarafa_search/plugin_solr.py  \
	zarafa_search/plugin_xapian.py  \
	zarafa_search/xmltotext.xslt

install-exec-local:
	cd ${srcdir} && ${PYTHON} setup.py install -f \
		$${DESTDIR+--root=${DESTDIR}} \
		--prefix="${prefix}" --install-purelib ${pythondir}
	rm -Rf build

install-data-local:
	mkdir -p "${DESTDIR}${localstatedir}/lib/zarafa/search"
