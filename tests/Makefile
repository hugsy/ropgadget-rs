CC_WIN_32 	:= i686-w64-mingw32-gcc
CC_WIN_64 	:= x86_64-w64-mingw32-gcc
CC_LIN_32 	:= gcc -m32
CC_LIN_64 	:= gcc -m64

CFLAGS		:=
LDFLAGS 	:=
SRC_DIR 	:= src
BIN_DIR 	:= bin

TARGET 		:= bin-win-32.exe bin-win-64.exe bin-lin-32.out bin-lin-64.out
.PHONY 		:= $(TARGET)  clean


all: $(TARGET)


bin-win-32.exe:
	$(CC_WIN_32)  $(CFLAGS) -D_WINDOWS_TARGET $(SRC_DIR)/test_x32.c -o $(BIN_DIR)/$@ $(LDFLAGS)

bin-win-64.exe:
	$(CC_WIN_64)  $(CFLAGS) -D_WINDOWS_TARGET $(SRC_DIR)/test_x64.c -o $(BIN_DIR)/$@ $(LDFLAGS)


bin-lin-32.out:
	$(CC_LIN_32)  $(CFLAGS) $(SRC_DIR)/test_x32.c -o $(BIN_DIR)/$@ $(LDFLAGS)

bin-lin-64.out:
	$(CC_LIN_64)  $(CFLAGS) $(SRC_DIR)/test_x64.c -o $(BIN_DIR)/$@ $(LDFLAGS)


clean:
	rm -fr -- $(BIN_DIR)/bin-*