tests:
	cd python2 && python2.4 httplib2test.py
	-cd python2 && python2.5 httplib2test.py
	cd python2 && python2.6 httplib2test.py
	cd python3 && python3.1 httplib2test.py

VERSION = $(shell python setup.py --version)
DST = dist/httplib2-$(VERSION)

release:
	-find . -name "*.pyc" | xargs rm 
	-find . -name "*.orig" | xargs rm 
	-rm -rf python2/.cache
	-rm -rf python3/.cache
	-mkdir dist
	-rm -rf dist/httplib2-$(VERSION)
	-rm dist/httplib2-$(VERSION).tar.gz
	-rm dist/httplib2-$(VERSION).zip
	-mkdir dist/httplib2-$(VERSION)
	cp -r python2 $(DST) 
	cp -r python3 $(DST) 
	cp setup.py README MANIFEST CHANGELOG $(DST)
	cd dist && tar -czv -f httplib2-$(VERSION).tar.gz httplib2-$(VERSION) 
	cd dist && zip httplib2-$(VERSION).zip -r httplib2-$(VERSION)

doc:
	#pudge -v -f --modules=httplib2 --dest=build/doc 

register:
	python setup.py register
