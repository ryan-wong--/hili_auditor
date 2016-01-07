#-----------------------------------------------------------------------------
# Makefile for db2 module    
#-----------------------------------------------------------------------------
X86=1

OBJ_DIR = obj
TARGET = test
COMPONENTS_ROOT = ../hili_tcp_mitm


CC := gcc
CCFLAGS = -g -O2 -W -Wall -Wno-unused -MD -Wno-unused-parameter -DX86=1 -DOCTEON_MODEL=OCTEON_CN66XX
CCINCLUDE = -I./ -I../hili_common -I../hili_dummy_mitm -I../hili_se_send_2_linux -I../OCTEON-SDK-juson/executive \
-I../../config \
-I../hili_tcp_mitm/components/common/config \
-I../hili_tcp_mitm/components/tcp/config \
-I../hili_tcp_mitm/components/socket/config \
-I../hili_tcp_mitm/components/common \




OBJ = hili_db2_parser

#provide a ".o" suffix for each word in OBJ
OBJECTS = $(OBJ:%=$(OBJ_DIR)/%.o)

$(OBJ_DIR)/%.o : %.c
	$(CC) -c -o $@ $< $(CCFLAGS) $(CCINCLUDE)

test: fifo_cache  $(OBJECTS)
	$(CC) -o $(OBJ_DIR)/test $(OBJECTS) $(OBJ_DIR)/fifo_cache.o
	$(OBJ_DIR)/test

fifo_cache : ../hili_common/fifo_cache.c
	$(CC) -c  -o $(OBJ_DIR)/fifo_cache.o $< $(CCFLAGS) $(CCINCLUDE)	


	
	
.PHONY : clean
clean:
	rm -f $(OBJ_DIR)/* $(TARGET)
