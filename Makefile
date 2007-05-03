release:
	python2.4 setup.py sdist --formats=gztar,zip
doc:
	#pudge -v -f --modules=httplib2 --dest=build/doc 
	/usr/lib/python2.5/doc/tools/mkhowto --html ref.tex
