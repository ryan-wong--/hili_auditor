
#
#  hili-http-parser Makefile fragment
#

#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)

#  component specification

LIBRARY := $(OBJ_DIR)/hili_db2_parser.a

OBJS_$(d)  :=  $(OBJ_DIR)/hili_db2_parser.o \

$(OBJS_$(d)):  CFLAGS_LOCAL := -I$(d) -g -O2 -Wall -fno-strict-aliasing

#  standard component Makefile rules

DEPS_$(d)   :=  $(OBJS_$(d):.o=.d)

LIBS_LIST   :=  $(LIBS_LIST) $(LIBRARY)

CLEAN_LIST  :=  $(CLEAN_LIST) $(OBJS_$(d)) $(DEPS_$(d)) $(LIBRARY)

-include $(DEPS_$(d))

$(LIBRARY): $(OBJS_$(d))
	$(AR) -r $@ $^

$(OBJ_DIR)/%.o:	$(d)/%.c
	$(COMPILE)  $(HILI_APP_INCLUDE)

$(OBJ_DIR)/%.o:	$(d)/%.S
	$(COMPILE)  $(HILI_APP_INCLUDE)

#  standard component Makefile footer

d   :=  $(dirstack_$(sp))
sp  :=  $(basename $(sp))

