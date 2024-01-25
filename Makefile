all:
	clang main.m -framework Foundation -o inject_arm64 -arch arm64
	clang main.m -framework Foundation -o inject_arm64e -arch arm64e
