rwildcard=$(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2) $(filter $(subst *,%,$2),$d))
OBJS=$(subst .cpp,.o,$(call rwildcard,,*.cpp)) $(subst .c,.o,$(call rwildcard,,*.c))
BINS=$(subst .cpp,.bin,$(call rwildcard,,*.cpp))
HEADERS=$(call rwildcard,,*.h)

CXXFLAGS ?= -std=c++2a
LIBS ?= -lxenlight -lxentoollog -lxenstore -lpam -lpam_misc -liniparser4 -lsmartcols -lmount -lxlutil -lblkid

all: wb

libproj.a: $(OBJS)
	ar r $@ $(OBJS)

%.bin: %.cpp libproj.a
	g++ $(CXXFLAGS) -o $@ -D__MAIN_MODULE__ $< -L . -lproj $(LIBS)

%.o: %.cpp $(HEADERS)
	g++ $(CXXFLAGS) -c $< -o $@

%.o: %.c $(HEADERS)
	gcc $(CFLAGS) -c $< -o $@

wb: wb.cpp libproj.a
	g++ $(CXXFLAGS) -o $@ -D__MAIN_MODULE__ wb.cpp -L . -lxenlight -lxentoollog -lxenstore -lpam -lpam_misc -liniparser4 -lsmartcols -lmount -lxlutil -lblkid -lproj

install: wb
	cp -a wb /usr/sbin/

clean:
	rm -f $(BINS) $(OBJS) libproj.a wb
