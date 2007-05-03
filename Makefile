release:
	python2.4 setup.py sdist --formats=gztar,zip
doc:
	pudge -v -f --modules=httplib2 --dest=build/doc 
	#./mkhowto --html ref.tex
