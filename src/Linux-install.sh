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
fi
echo "- - - - - - - - - - - - - - - - - - -"
echo "Checking cmake..."
if command -v cmake --version >/dev/null 2>&1 ; then
    echo "OK! $(cmake --version)"
else
    echo "cmake not found, installing..."
    sudo apt-get install -y cmake
    if [ $? != 0 ]; then
        echo "!!!!! Command exited with $? code !!!!!"
        echo "Can't move on. Exiting process, because cmake installation went wrong ... Consider manual build. Bye!"
        exit -1
    else
        echo "Installation of cmake complete!"
    fi
fi
echo "- - - - - - - - - - - - - - - - - - -"
echo "Checking cJSON..."
FOUND=0
for LINE in $(sudo find / -name ".git" 2>/dev/null)
    do
	STRING=`echo $(cat $LINE/config | grep url)`
	URL="url = https://github.com/DaveGamble/cJSON.git"
	if [[ "$STRING" == *"$URL"* ]]; then
	    cd $LINE
		echo "OK! Version: $(git describe --tags)"
	    FOUND=1
	    cd ..
        break
	fi
    done
if [ $FOUND = 0 ]; then
    echo "cJSON not found, downloading..."
    cd /home/${SUDO_USER:-${USER}}
    git clone https://github.com/DaveGamble/cJSON.git
    if [ $? != 0 ]; then
        echo "!!!!! Command exited with $? code !!!!!"
        echo "Can't move on. Exiting process, because cJSON 'git clone' went wrong ... Consider manual build. Bye!"
        exit -1
    else
        echo "Download of cJSON successfull!"
        cd cJSON
        mkdir build
        if [ $? != 0 ]; then
            echo "!!!!! Command exited with $? code !!!!!"
            echo "Can't move on. Exiting process, because cJSON 'mkdir' went wrong ... Consider manual build. Bye!"
            exit -1
        fi
        cd build
        cmake .. -DENABLE_CJSON_UTILS=On -DENABLE_CJSON_TEST=Off -DCMAKE_INSTALL_PREFIX=/usr
        if [ $? != 0 ]; then
            echo "!!!!! Command exited with $? code !!!!!"
            echo "Can't move on. Exiting process, because cJSON 'cmake' went wrong ... Consider manual build. Bye!"
            exit -1
        fi
        make ..
        if [ $? != 0 ]; then
            echo "!!!!! Command exited with $? code !!!!!"
            echo "Can't move on. Exiting process, because cJSON 'make' went wrong ... Consider manual build. Bye!"
            exit -1
        fi
        make DESTDIR=$pkgdir install
        if [ $? != 0 ]; then
            echo "!!!!! Command exited with $? code !!!!!"
            echo "Can't move on. Exiting process, because cJSON 'make install' went wrong ... Consider manual build. Bye!"
            exit -1
        fi
    fi
fi

cd ${SCRIPT_DIR}
make all >/dev/null 2>&1

echo ""
echo "- - - - - - - - - - - - - - - - - - -"
echo "=== ALL CLEAR - ENJOY! BYE! ==="

exit 0