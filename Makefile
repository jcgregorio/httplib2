release:
	python2.4 setup.py sdist --formats=gztar,zip
doc:
	./mkhowto --html ref.tex
