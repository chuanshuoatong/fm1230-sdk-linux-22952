# fm1230-sdk-linux-22952
复旦微加密芯片 fm1230 的demo sdk

1. compile:
	make clean
	make
2. push to your device: 
	adb push se_demo /data/
3. run it:
	adb root & adb shell
	chmod a+x /data/se_demo
	./data/se_demo
