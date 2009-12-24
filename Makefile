tests:
	python httplib2test.py

release:
	tar -czv -f dist/httplib2.tar.gz 
	#python setup.py sdist --formats=gztar,zip

doc:
	#pudge -v -f --modules=httplib2 --dest=build/doc 

register:
	python setup.py register
