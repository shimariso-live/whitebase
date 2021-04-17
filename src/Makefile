rwildcard=$(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2) $(filter $(subst *,%,$2),$d))
OBJS=$(subst .cpp,.o,$(call rwildcard,,*.cpp)) $(subst .c,.o,$(call rwildcard,,*.c))
BINS=$(subst .cpp,.bin,$(call rwildcard,,*.cpp))
HEADERS=$(call rwildcard,,*.h)

CXXFLAGS ?= -std=c++2a
LIBS ?= -lpam -lpam_misc -liniparser4 -lmount -lxenlight -lxlutil -lblkid -lsystemd -lutil -lPocoNet -lPocoNetSSL -lPocoFoundation -lPocoJSON -lssl -lcrypto -licuuc -lSDL2 -lSDL2_image -lSDL2_ttf -lvterm

all: wb walbrixd wg-walbrix messages.mo textui xendomain

libproj.a: $(OBJS)
	ar r $@ $(OBJS)

%.bin: %.cpp libproj.a
	g++ $(CXXFLAGS) -o $@ -D__MAIN_MODULE__ $< -L . -lproj $(LIBS)

%.o: %.cpp $(HEADERS)
	g++ $(CXXFLAGS) -c $< -o $@

%.o: %.c $(HEADERS)
	gcc $(CFLAGS) -c $< -o $@

wb: wb.cpp libproj.a
	g++ $(CXXFLAGS) -o $@ -D__MAIN_MODULE__ wb.cpp -L . -lutil -licuuc -lSDL2 -lSDL2_image -lSDL2_ttf -lvterm -lpam -lmount -lblkid -lproj

walbrixd: walbrixd.cpp
	g++ $(CXXFLAGS) -o $@ -D__MAIN_MODULE__ $^ -lsystemd -lutil

wg-walbrix: wg-walbrix.cpp
	g++ $(CXXFLAGS) -o $@ -D__MAIN_MODULE__ $^ -lsystemd -lutil -lPocoNet -lPocoNetSSL -lPocoFoundation -lPocoJSON -lssl -lcrypto

textui: textui.cpp termbox.o
	g++ $(CXXFLAGS) -o $@ -lpam -lpam_misc -D__MAIN_MODULE__ $^

xendomain: xendomain.cpp
	g++ $(CXXFLAGS) -o $@ -D__MAIN_MODULE__ $^ -lxenlight -lxentoollog -lxenstore -liniparser4

messages.mo: messages.po
	msgfmt -o $@ $<

install: wb walbrixd walbrixd.service walbrixd.conf wg-walbrix textui xendomain wg-walbrix.service wg-walbrix.conf messages.mo
	cp -a wb walbrixd wg-walbrix textui xendomain /usr/sbin/
	cp -a walbrixd.service wg-walbrix.service /lib/systemd/system/
	cp -a walbrixd.conf wg-walbrix.conf /etc/dbus-1/system.d/
	mkdir -p /usr/share/wb/themes/default
	cp -a default_theme/. /usr/share/wb/themes/default/
	cp -a messages.mo /usr/share/locale/ja/LC_MESSAGES/

clean:
	rm -f $(BINS) $(OBJS) libproj.a wb walbrixd wg-walbrix
