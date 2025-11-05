all: bchoc

bchoc:
	chmod +x bchoc.py
	ln -sf bchoc.py bchoc

clean:
	rm -f bchoc
	rm -f *.pyc
	rm -rf __pycache__

.PHONY: all clean
