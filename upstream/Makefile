
INSTALL_PREFIX=/opt/api-gateway

LIBS=-lm -lpthread -ljson-c
LIBS += $(shell pkg-config --cflags --libs libsoup-2.4)

all: auth_proxy
auth_proxy:
	gcc -std=gnu99 -g -Wall -o auth_proxy auth_proxy.c $(LIBS)
	

.PHONY: clean install uninstall install-daemon
clean:
	rm auth_proxy
	
install: auth_proxy
	mkdir -p $(INSTALL_PREFIX)/bin
	mkdir -p $(INSTALL_PREFIX)/config
	cp -p auth_proxy $(INSTALL_PREFIX)/bin/

uninstall:
	rm $(INSTALL_PREFIX)/bin/auth_proxy
	
install-daemon: 
	cp -p auth_proxy.service /etc/systemd/system/
	systemctl start auth_proxy
	systemctl enable auth_proxy
	




