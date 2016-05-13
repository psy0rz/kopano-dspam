[ ! "$1" ] && exit 1
while true; do 
    MD5=`ls -lcRi --time-style=+%s | md5sum`
    if [ "$MD5" != "$UPLOADEDMD5" ]; then
         if rsync --exclude '.*' --delete -e ssh -v -a . $1:zarafa-spamd.git ;then
         	UPLOADEDMD5="$MD5"
	 fi
    fi
    sleep 5;
done
