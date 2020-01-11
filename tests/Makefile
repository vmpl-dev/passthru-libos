c_executables   = $(patsubst %.c,%,$(wildcard *.c))
cxx_executables = $(patsubst %.cpp,%,$(wildcard *.cpp))

$(c_executables): %: %.c
	gcc -o $@ $<

$(cxx_executables): %: %.cpp
	g++ -o $@ $<

clean:
	$(RM) $(c_executables) $(cxx_executables)
