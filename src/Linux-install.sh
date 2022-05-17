#!/bin/bash
if [ `id -u` != 0 ]; then
    echo "Error: this script must be run as root."
    exit -1
fi

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
echo "=== CHECKING APPLiCATION DEPENDENCIES ==="
echo "- - - - - - - - - - - - - - - - - - -"
echo "Checking GTK..."
if command -v gtk-launch --version >/dev/null 2>&1 ; then
    echo "OK! Version: $(gtk-launch --version)"
else
    echo "GTK not found, installing..."
    sudo apt-get install -y libgtk-3-dev
    if [ $? != 0 ]; then
        echo "!!!!! Command exited with $? code !!!!!"
        echo "Can't move on. Exiting process, because GTK installation went wrong ... Consider manual build. Bye!"
        exit -1
    else
        echo "Installation of GTK complete!"
    fi
fi
echo "- - - - - - - - - - - - - - - - - - -"
echo "Checking OpenSSL..."
if command -v apt-cache show openssl >/dev/null 2>&1 ; then
    echo "OK! $(apt-cache show openssl | grep Version)"
else
    echo "OpenSSL not found, installing..."
    sudo apt-get install -y libssl-dev
    if [ $? != 0 ]; then
        echo "!!!!! Command exited with $? code !!!!!"
        echo "Can't move on. Exiting process, because OpenSSL installation went wrong ... Consider manual build. Bye!"
        exit -1
    else
        echo "Installation of OpenSSL complete!"
    fi
find
cd ${SCRIPT_DIR}
make all >/dev/null 2>&1

echo ""
echo "- - - - - - - - - - - - - - - - - - -"
echo "=== ALL CLEAR - ENJOY! BYE! ==="

exit 0