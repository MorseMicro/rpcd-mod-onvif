SOAPLIB = soaplib/stdsoap2.o soaplib/dom.o \
          soaplib/soapC.o soaplib/soapClient.o \
          soaplib/wsaapi.o soaplib/wsddapi.o \
          soaplib/wsseapi.o soaplib/mecevp.o soaplib/smdevp.o soaplib/struct_timeval.o

CFLAGS += -Os -I soaplib -DWITH_NONAMESPACES -DWITH_OPENSSL -DWITH_DOM -DWITH_ZLIB -fPIC -fdata-sections -ffunction-sections -fvisibility=hidden
# _GNU_SOURCE is needed for soapC.c and the ifdef there seems broken. Quickfix; should fix patch.
CFLAGS += -D_GNU_SOURCE
LDFLAGS += -Wl,--gc-sections
LDLIBS += -lcrypto -lssl -lz -lubox -lubus

onvif.so: onvif.c $(SOAPLIB)
	$(CC) -shared $(CFLAGS) $(LDFLAGS) $(SOAPLIB) -Wall -Werror -fvisibility=default onvif.c -o onvif.so $(LDLIBS)

.PHONY: clean
clean:
	# Don't nuke the generated files; we most likely just care about the objects
	rm -f onvif.so $(SOAPLIB)
