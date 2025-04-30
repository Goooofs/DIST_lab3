# DIST_lab3

x86_64-w64-mingw32-g++ -static -o TargetProcess.exe TargetProcess.cpp
x86_64-w64-mingw32-g++ -static -shared -Wl,--subsystem,windows -o VirusDLL.dll VirusDLL.cpp
x86_64-w64-mingw32-g++ -static -o DLLLoader.exe DLLLoader.cpp
x86_64-w64-mingw32-g++ -static -o DLLInjectorAsProcess.exe DLLInjectorAsProcess.cpp
x86_64-w64-mingw32-g++ -static -o TargetProcessWithProtection.exe TargetProcessWithProtection.cpp