all: build

SRC=wpaspy.c

build: $(SRC) setup.py
	python3 setup.py build

install:
	python3 setup.py install

clean:
	python3 setup.py clean
	rm -f *~
	rm -rf build
