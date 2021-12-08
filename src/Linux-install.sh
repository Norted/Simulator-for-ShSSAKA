#!/bin/bash
if [ `id -u` != 0 ]; then
    echo "Error: this script must be run as root."
    exit -1
fi

echo "=== CHECKING PROGRAMM DEPENDENCIES ==="
echo "- - - - - - - - - - - - - - - - - - -"
echo "Checking GTK..."
# https://www.gtk.org/docs/installations/linux/

"""
# TODO:
if command -v dsniff >/dev/null 2>&1 ; then
    echo "OK! $(dsniff -h |& grep Version:)"
else
    echo "dsniff not found, installing..."
    sudo apt-get install -y dsniff
    if [ $? != 0 ]; then
        echo "!!!!! Command exited with $? code !!!!!"
    else
        echo "Installation of dsniff complete!"
    fi
fi

echo "- - - - - - - - - - - - - - - - - - -"
echo "Checking jtesta's ssh-mitm..."
FOUND_TESTA=0
FOUND_APP=0
for LINE in $(sudo find / -name ".git" 2>/dev/null)
    do
	STRING=`echo $(cat $LINE/config | grep url)`
	URL_TESTA="url = https://github.com/jtesta/ssh-mitm"
	URL_APP="url = https://github.com/Norted/KRY-project"
	if [[ "$STRING" == *"$URL_TESTA"* ]]; then
	    cd $LINE
		echo "OK! Version: $(git describe --tags)"
	    FOUND_TESTA=1
	    TESTA_DIR=${LINE%"/.git"}
	    cd ..
	elif [[ "$STRING" == *"$URL_APP"* ]]; then
	    FOUND_APP=1
	    APP_DIR=${LINE%"/.git"}
	fi
    done
if [ $FOUND_TESTA = 0 ]; then
    echo "jtesta's ssh-mitm not found, downloading..."
    cd /home/${SUDO_USER:-${USER}}
    git clone  https://github.com/jtesta/ssh-mitm.git
    if [ $? != 0 ]; then
        echo "!!!!! Command exited with $? code !!!!!"
        echo "Can't move on. Exiting process, because something went wrong ... Bye!"
        exit -1
    else
        echo "Download of ssh-mitm successfull!"
        cd ssh-mitm
    fi
elif [[ "$TESTA_DIR" == *"$APP_DIR"* ]]; then
    echo "Moving ssh-mitm dir..."
    OLD_DIR=$TESTA_DIR
    NEW_DIR=$(echo $TESTA_DIR | rev | cut -d'/' -f3- | rev)
    echo "Moving $OLD_DIR to $NEW_DIR"
    mv $OLD_DIR $NEW_DIR
    TESTA_DIR="${TESTA_DIR%"${TESTA_DIR##*[!/]}"}"
    TESTA_DIR="$NEW_DIR/${TESTA_DIR##*/}"
fi

echo "+ + + + + + + + + + + + + + + + + + +"
sudo ./install.sh
echo "+ + + + + + + + + + + + + + + + + + +"

echo "=== DEPENDENCIES CHECKED ==="

echo ""
echo "- - - - - - - - - - - - - - - - - - -"
echo "- - - - - - - - - - - - - - - - - - -"
echo ""

echo "=== PREPARING APPLICATION ==="
if [ $FOUND_APP = 1 ]; then
    echo "Repository of the application was found!"
    if [[ "$APP_DIR" == *"$TESTA_DIR"* ]]; then
        echo "OK! Application in it's position!"
    else
        echo "Moving application in ssh-mitm dir..."
        echo "Moving $APP_DIR to $TESTA_DIR"
	mv $APP_DIR $TESTA_DIR
    fi
else
    echo "Application not found, dowloading..."
        git clone https://github.com/Norted/KRY-project.git
        if [ $? != 0 ]; then
            echo "!!!!! Command exited with $? code !!!!!"
        else
            echo "Download of the aplication successfull!"
        fi
fi

echo "- - - - - - - - - - - - - - - - - - -"
echo "=== CREATING DESKTOP SHORTCUT ==="
GUI=$(find "$(cd ..; pwd)" -name "GUI.py")
ICON=$(find "$(cd ..; pwd)" -name "monster-cartoon.svg")

cd /home/${SUDO_USER:-${USER}}/Desktop
touch AutoSSHMitM.desktop
sudo chmod +x AutoSSHMitM.desktop
cat << EOF > AutoSSHMitM.desktop
[Desktop Entry]
Version=1.0
Type=Application
Name=AutoSSHMitM
Comment=AutoSSHMitM launcher
Icon=$ICON
Exec=sudo python3 GUI.py
Terminal=true
StartupNotify=false
Path=${GUI%"/GUI.py"}
EOF
echo "Desktop shortcut created!"
"""

echo ""
echo "- - - - - - - - - - - - - - - - - - -"
echo "- - - - - - - - - - - - - - - - - - -"
echo "=== ALL CLEAR - ENJOY! BYE! ==="

exit 0