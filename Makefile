
TOOLS := arm-none-linux-gnueabi-gcc
OBJS := fmse_drv.o tdes.o fmse_cmd.o fmse_demo.o
TARGET := se_demo
FLAGS := -static

$(TARGET):$(OBJS)
	$(TOOLS) $(FLAGS) $^ -o $@

%.o : %.c
	$(TOOLS) -c $^ -o $@
	
.PHONY clean:
	rm -rf *.o $(TARGET)
	
