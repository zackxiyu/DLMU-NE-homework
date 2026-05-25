main: src/main.c
	gcc src/main.c -o src/main.exe -I./include $(shell pkg-config --cflags --libs gtk+-3.0) -L"/c/Program Files/npcap-sdk/Lib/x64" -lwpcap -lws2_32
	./src/main.exe

clean:
	rm -f src/main.exe