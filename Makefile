include ../Makefile.kernel

# userprog/Makefile에 아래 추가
disk:
	$(MAKE) -C build disk