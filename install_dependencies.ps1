# Install ALL dependencies needed to build Cleo.
# Used Vcpkg for installing dependencies (docs: https://github.com/microsoft/vcpkg)
# Vcpkg install tutorial: https://vcpkg.io/en/getting-started.html
# Recomended to build/compile Cleo on Microsoft Visual Studio, Windows, Release Mode and on arch x86.
# Note: Every library should be statically linked.
./vcpkg integrate install
./vcpkg install curl:x86-windows-static
./vcpkg install cpr:x86-windows-static
./vcpkg install jsoncpp
echo Finished
