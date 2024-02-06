all:
	clang main.c -framework Foundation -o inject_arm64 -arch arm64 -framework Security
	clang main.c -framework Foundation -o inject_arm64e -arch arm64e -framework Security
	clang main.c -D AMFI -framework Foundation -o inject_arm64ea -arch arm64e -framework Security -lbsm -lEndpointSecurity -Wno-unused-value
	codesign -f -s - --entitlements ent.plist ./inject_arm64ea
