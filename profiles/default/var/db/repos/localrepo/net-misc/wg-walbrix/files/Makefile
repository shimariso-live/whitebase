SRCS=wg-walbrix.cpp crypt.cpp common.cpp
OBJS=$(subst .cpp,.o,$(SRCS))
ALL=wg-walbrix libwg-walbrix.a
CXXFLAGS=-std=c++20
LIBS=-lyajl -lssl -lcrypto -liniparser4

all: $(ALL)

.cpp.o:
	g++ $(CXXFLAGS) -g -c $< -o $@

libwg-walbrix.a: $(OBJS)
	ar r $@ $(OBJS)

wg-walbrix: $(SRCS)
	g++ $(CXXFLAGS) -o $@ $(SRCS) $(LIBS) -lcurl

libnss_wg_walbrix.so: $(SRCS)
	g++ $(CXXFLAGS) -o $@ -D NSS_MODULE $^ -fPIC -shared -Wl,-soname,libnss_wg_walbrix.so.2 $(LIBS)

install: all
	install wg-walbrix $(DESTDIR)/usr/lib64/libnss_wg_walbrix.so.2

clean:
	rm -f $(ALL) *.o


