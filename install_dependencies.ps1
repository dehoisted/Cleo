#Requires -RunAsAdministrator

echo "Installing needed dependencies for CLEO v5 build process!"
echo "Please hang tight!"

$path = Read-Host -Prompt 'Please enter your VCPKG INSTALLATION PATH: '

if(Test-Path -Path $path -PathType Leaf == False) {
  echo "No installation could be found..."
  pause
  exit
}

vcpkg integrate install
vcpkg install curl:x86-windows-static
vcpkg install cpr:x86-windows-static
vcpkg install jsoncpp
