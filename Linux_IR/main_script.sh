#!/bin/sh

rm -rf ./auto_script_output 2>/dev/null

OUTPUT=auto_script_output
MNT_LOCATION=/

while getopts "o:m:" opt; do
  case $opt in
    o) OUTPUT="$OPTARG";;
    m) MNT_LOCATION="$OPTARG";;
    \?) echo "Invalid option -$OPTARG" >&2
    ;;
  esac
done

echo -n "Creating the output directory: $OUTPUT"...
mkdir $OUTPUT
cd $OUTPUT
echo " done."



### OS Version ###
echo -n "Finding OS Version... "
if [ "$MNT_LOCATION" = "/" ];then
	uname -a >> os_version.txt
fi
cat $MNT_LOCATION/etc/os-release >> os_version.txt
echo " done."

### Host Installation time ###
echo -n "Finding Host Installation Date... "
ls -l $MNT_LOCATION/etc/ssh/ssh_host_*_key | awk -F" " 'NR==1{print $6"-"$7" "$8}' >> potential_os_installation_date.txt
echo " done."

### Static IP addresses ###
echo -n "Finding Static IP addresses... "
cat $MNT_LOCATION/etc/hosts >> static_ip_addresses.txt
echo " done."

### Get live data
if [ "$MNT_LOCATION" = "/" ];then
	echo -n "Getting Live Data..."
	echo -n "ps done... "
	ps -auwx >> running_processes.txt
	# echo "==== Netstat ====\n" >> active_connections.txt;
	echo -n "netstat done... "
	netstat -antp >> active_connections_netstat.txt
	ss -tulpn >> active_connections_ss.txt
	echo "ss done."
fi

### Gettings users with directories lists ###
# users with bash
echo -n "Finding users with bash... "
cat $MNT_LOCATION/etc/passwd | grep bash | grep -v root | awk -F":" '{print $1}' > users.txt
echo " done."
echo -n "Finding all users... "
cat $MNT_LOCATION/etc/passwd | awk -F":" '{print $1}' > users_all.txt


# users in /home
ls $MNT_LOCATION/home >> users.txt

# cleanup
cat users.txt | sort -u > users1.txt
mv users1.txt users.txt
echo " done."

### Users with SUID=0
echo -n "Finding users with SUID set to 0... "
cat $MNT_LOCATION/etc/passwd | grep :0: >> users_suid_eq_0.txt
echo " done."

### Users who can run sudo
echo -n "Finding users who can run sudo command... "
cat $MNT_LOCATION/etc/group | grep '^sudo:.$MNT_LOCATION*$' | awk -F":" '{print $NF}' >> users_sudo.txt
cat $MNT_LOCATION/etc/sudoers.d/* | grep -v "#" >> users_sudo_list.txt
echo " done."

### Bash history ###
echo -n "Dumping all the user's bash histories..."
for user in $(cat users.txt)
do
	mkdir $user
	cat $MNT_LOCATION/home/$user/.bash_history > $user/bash_history_$user.txt 2> /dev/null
done
echo " done."

## root user's bash history
echo -n "Dumping root's bash histories..."
mkdir root
cat $MNT_LOCATION/root/.bash_history > root/bash_history_root.txt 2> /dev/null
echo " done."

### log files ###
echo -n "Dumping logs..."
mkdir logs

# auth.log
echo -n " auth.log done... "
cat $MNT_LOCATION/var/log/auth.log | grep -a "COMMAND" > logs/auth_commands.log
### /var/log/secure
### /var/log/audit/audit.log

# wtmp, utmp and btmp logs
echo -n " wtmp done... "
last -f $MNT_LOCATION/var/log/wtmp > logs/wtmp_logs.txt 2> /dev/null
echo -n " utmp done... "
last -f $MNT_LOCATION/var/log/utmp > logs/utmp_logs.txt 2> /dev/null
echo " btmp done... "
last -f $MNT_LOCATION/var/log/btmp > logs/btmp_logs.txt 2> /dev/null


### Get browser information... ###
# Firefox
echo -n "Finding browser history... "
for user in $(cat users.txt)
do
	mkdir $user/firefox_data
	## places.sqlite -> Firefox history
	find $MNT_LOCATION/home/$user/.mozilla/ -name places.sqlite >> $user/firefox_data/places_db_$user.txt 2> /dev/null
	mkdir $user/firefox_data/browsing_history
	for place in $(cat $user/firefox_data/places_db_$user.txt)
	do
		# copies all places_.sqlite file and renames them according through their profile...
		cp $place $user/firefox_data/browsing_history/$(cat $user/firefox_data/places_db_$user.txt | grep $place | awk -F"/" '{print $6}')_places.sqlite 2> /dev/null
		# get the contents from the database and dump it to a txt file
		sqlite3 $place "select h.visit_date,p.url from moz_historyvisits as h, moz_places as p where p.id == h.place_id order by h.visit_date" > $user/firefox_data/browsing_history/$(cat $user/firefox_data/places_db_$user.txt | grep $place | awk -F"/" '{print $6}')_browsing_history.txt 2> /dev/null
	done

	## 
done
echo " done."

# Chromium

# echo -n "Finding  ..."
# echo " done."

### tmp directory ###
echo -n "Finding files in /tmp ..."
find $MNT_LOCATION/tmp > tmp_directory_list.txt
echo " done."
#... maybe cat out the data (?)

### currently loggedon users ###
if [ "$MNT_LOCATION" = "/" ];then
	echo -n "Finding  currently logged on users..."
	who > users_loggedon.txt
	w > users_loggedon_moreinfo.txt
	echo " done."
fi

### users login history ###
if [ "$MNT_LOCATION" = "/" ];then
	echo -n "Finding user's login history..."
	last > users_login_history.txt
	echo " done."
fi

### Opened files ###
if [ "$MNT_LOCATION" = "/" ];then
	echo -n "Finding recently opened files..."
	lsof > opened_files.txt 2> /dev/null
	echo " done."
fi

### Crontab and scheduled tasks ###
echo -n "Finding all cronjobs..."
if [ "$MNT_LOCATION" = "/" ];then
	for user in $(cat users.txt)
	do	
		crontab -l -u $user >> list_scheduled_tasks_crontab_$user.txt 2> /dev/null
	done
fi

## crontab
cat $MNT_LOCATION/etc/crontab >> list_cronjobs.txt

## users cronjobs 
find $MNT_LOCATION/var/spool/cron/crontabs/ -type f -print -exec cat {} \; >> listed_user_cronjobs.txt

## all other cronjobs
find $MNT_LOCATION/etc/cron.d -type f -print -exec cat {} \; >> listed_cron.d.txt
find $MNT_LOCATION/etc/cron.daily -type f -print -exec cat {} \; >> listed_cron.daily.txt
find $MNT_LOCATION/etc/cron.hourly -type f -print -exec cat {} \; >> listed_cron.hourly.txt
find $MNT_LOCATION/etc/cron.weekly -type f -print -exec cat {} \; >> listed_cron.weekly.txt

echo " done."

### Latest modified/created files init.d/
echo -n "Finding recently modified files in init.d..."
ls -lt $MNT_LOCATION/etc/init.d/ | awk -F" " '{print $6"-"$7" "$8":\t"$9}' | grep -v "\- :" > startup_files_initd_recently_modified.txt
echo " done."

### Latest modified/created files systemd/
echo -n "Finding recently modified files in systemd..."
ls -lt $MNT_LOCATION/etc/systemd/system | awk -F" " '{print $6"-"$7" "$8":\t"$9}' | grep -v "\- :" > startup_files_systemd_recently_modified.txt
echo " done."

### SSH files (authorized_keys entries)
echo -n "Finding users SSH files..."
for user in $(cat users.txt)
do
	mkdir $user/ssh_files
	cat $MNT_LOCATION/home/$user/.ssh/authorized_keys > $user/ssh_files/authorized_keys 2> /dev/null
done

# root SSH
cat $MNT_LOCATION/root/.ssh/authorized_keys > root/authorized_keys 2> /dev/null
echo " done."

### Dump "interesting" files

echo -n "Finding 'interesting' files ..."
# Files owned by user root
find $MNT_LOCATION/ -perm -4000 -user root -type f >> files_owned_by_root.txt 2> /dev/null

# Checks for SGID files
find $MNT_LOCATION/ -perm /6000 -type f >> files_sgid.txt 2> /dev/null

# Checks for files updated within last 7 days
find $MNT_LOCATION/ -mtime -7 -o -ctime -7 >> files_updated_recently.txt 2> /dev/null

echo " done."

### Dump hashes of all the files
echo -n "Dumping hashes of all the files (this might take some time)..."
find $MNT_LOCATION/ -type f -exec md5sum {} >> hashes_of_all_files.txt \; 2> /dev/null
echo " done."