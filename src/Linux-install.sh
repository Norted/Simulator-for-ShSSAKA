#!/bin/bash
if [ `id -u` != 0 ]; then
    echo "Error: this script must be run as root."
    exit -1
fi

echo "=== CHECKING APPLiCATION DEPENDENCIES ==="
echo "- - - - - - - - - - - - - - - - - - -"
echo "Checking GTK..."
if command -v gtk-launch --version >/dev/null 2>&1 ; then
    echo "OK! $(gtk-launch --version)"
else
    echo "GTK not found, installing..."
    sudo apt-get install -y libgtk-3-dev
    if [ $? != 0 ]; then
        echo "!!!!! Command exited with $? code !!!!!"
    else
        echo "Installation of GTK complete!"
    fi
fi
echo "Checking OpenSSL..."
if command -v openssl version >/dev/null 2>&1 ; then
    echo "OK! $(openssl version)"
else
    echo "OpenSSL not found, installing..."
    sudo apt-get install -y libssl-dev
    if [ $? != 0 ]; then
        echo "!!!!! Command exited with $? code !!!!!"
    else
        echo "Installation of OpenSSL complete!"
    fi
fi

echo ""
echo "- - - - - - - - - - - - - - - - - - -"
echo "=== ALL CLEAR - ENJOY! BYE! ==="

exit 0