@if [%2] == [] echo Insufficient parameters! && pause && exit

mkdir CMake.tmp
cd CMake.tmp
mkdir %1
cd %1
mkdir %2
cd %2

cmake --build . --config Release --target install
if %ERRORLEVEL% neq 0 pause && goto eof

:eof
cd ../../..
