gruntreceive-uucp: gruntreceive-uucp.c
	gcc -Wall -o gruntreceive-uucp gruntreceive-uucp.c

clean:
	rm -f *~ gruntreceive-uucp
	-rm `find . -name "*~"` `find . -name "*.pyc"` `find . -name "*.so"`
	-find . -name auth -exec rm -vf {}/password {}/username \;
	-svn cleanup
