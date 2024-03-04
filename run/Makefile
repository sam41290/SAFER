PROJDIR := $(realpath $(CURDIR)/..)
SOURCEDIR := $(PROJDIR)/src
BUILDDIR := $(realpath $(CURDIR))

TARGET = demo

VERBOSE = TRUE

DIRS = binary cfg disasm elf exception exe_manager randomization utils instrument 
SOURCEDIRS = $(foreach dir, $(DIRS), $(addprefix $(SOURCEDIR)/, $(dir)))
TARGETDIRS = $(foreach dir, $(DIRS), $(addprefix $(BUILDDIR)/, $(dir))) $(BUILDDIR)/run

INCLUDES = $(foreach dir, $(SOURCEDIRS), $(addprefix -I, $(dir))) -I$(BUILDDIR)

VPATH = $(SOURCEDIRS) $(BUILDDIR)


SOURCES = $(foreach dir,$(SOURCEDIRS),$(wildcard $(dir)/*.cpp))
SOURCE2 = $(foreach dir,$(BUILDDIR),$(wildcard $(dir)/*.cpp))

OBJS := $(subst $(SOURCEDIR),$(BUILDDIR),$(SOURCES:.cpp=.o)) $(subst $(BUILDDIR),$(BUILDDIR)/run,$(SOURCE2:.cpp=.o))


ifeq ($(OS),Windows_NT)
    RM = del /F /Q
    RMDIR = -RMDIR /S /Q
    MKDIR = -mkdir
	MV = ren
    ERRIGNORE = 2>NUL || true
    SEP=\\
else
    RM = rm -rf
    RMDIR = rm -rf
    MKDIR = mkdir -p
	MV = mv
    ERRIGNORE = 2>/dev/null
    SEP=/
endif

PSEP = $(strip $(SEP))

ifeq ($(VERBOSE),TRUE)
    HIDE = 
else
    HIDE = @
endif

DEPS = $(OBJS:.o=.d)
FINDEPS = $(foreach dep,$(DEPS),$(subst /,$(PSEP),$(dep)))

DEPFLAGS = -MMD -MP -MF $(1)$(PSEP)$$*.Td
POSTCOMPILE = $(MV) -f $(1)$(PSEP)$$*.Td $(1)$(PSEP)$$*.d && touch $$@

CXX = LD_LIBRARY_PATH=/usr/lib/ocaml g++ -O2
MCXXFLAGS := -g -Wall $(CXXFLAGS) $(CPPFLAGS) $(TARGET_ARCH)

CC = LD_LIBRARY_PATH=/usr/lib/ocaml gcc -O2

COMPILE.c = $(CC) $(DEPFLAGS) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c
COMPILE.C = $(CXX) $(DEPFLAGS) $(MCXXFLAGS) -c

define generateRules
$(1)/%.o: %.cpp $(1)$(PSEP)%.d
	@echo Building $$@
	$(HIDE)$(COMPILE.C) $$(INCLUDES) $(DEPFLAGS) -o $$(subst /,$$(PSEP),$$@) $$(subst /,$$(PSEP),$$<)
	$(POSTCOMPILE)
endef

.PHONY: all clean directories

all: directories $(TARGET)

$(TARGET): $(OBJS)
	$(HIDE)echo Linking $@
	$(HIDE)$(CXX) $(INCLUDES) -L../src/SBD/analysis $(OBJS) -o $(TARGET) -lcapstone -lopcodes -lanalysis_new

$(OBJS): $(foreach targetdir, $(TARGETDIRS), $(eval $(call generateRules, $(targetdir))))


$(FINDEPS):

-include $(DEPS)

directories:
	$(HIDE)$(MKDIR) $(subst /,$(PSEP),$(TARGETDIRS)) $(ERRIGNORE) jmp_table log 

clean:
	$(HIDE)$(RMDIR) $(subst /,$(PSEP),$(TARGETDIRS)) $(ERRIGNORE)
	$(HIDE)$(RM) $(TARGET) jmp_table log tmp/* *.o *.s text $(ERRIGNORE)
	@echo Cleaning done !
