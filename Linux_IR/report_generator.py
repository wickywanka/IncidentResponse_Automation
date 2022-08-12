#!/usr/bin/env python3

from notion.client import NotionClient
from notion.block import PageBlock
from md2notion.upload import upload
import json
import argparse
import tarfile

with open("config.json", "r") as f:
    config_data = json.loads(f.read())

token_notion = config_data["notion_token_v2"]
client = NotionClient(token_v2=token_notion)
page = client.get_block("https://www.notion.so/fakebatman/Report-for-Incident-Response-62cafa4e5990465fa87ccd49f28c0a52")


def upload_report(mdFilename, report_title):
    with open(mdFilename, "r", encoding="utf-8") as mdFile:
        newPage = page.children.add_new(PageBlock, title=report_title)
        upload(mdFile, newPage) #Appends the converted contents of TestMarkdown.md to newPage


def update_report_contents(report_contents, file_name, folder_location, section_title = "", section_sub_title = "", section_description = ""):
    try:
        if section_title != "":
            print("Uploading {}...".format(section_title), end="")
        elif section_sub_title != "":
            print("Uploading {}...".format(section_sub_title), end="")
        with open("{}/{}".format(folder_location, file_name)) as f:
            file_contents = str(f.read())
            if file_contents != "":
                if section_title != "":
                    report_contents += "\n## {}\n".format(section_title)
                if section_sub_title != "":
                    report_contents += "\n**{}**\n".format(section_sub_title)
                if section_description != "":
                    report_contents += "\n*{}*\n".format(section_description)
                
                report_contents += "```\n"
                report_contents += file_contents
                report_contents += "```\n"
                print("Done")
    except FileNotFoundError as e:
        # print("Ran into error while opening the file at {}/{}. Error: {}".format(folder_location, file_name, e))
        print("Not Found")
    finally:    
        return report_contents


def add_header(report_contents, header_content):
    report_contents += "\n## {}\n".format(header_content)
    return report_contents


def create_md_file(folder_location, report_title):
    report_contents = ""

    ### OS Version
    report_contents = update_report_contents(report_contents, "os_version.txt", folder_location, section_title="OS Version", section_description="OS Version and other details about the Linux distro installed")

    ### Host Installation time
    report_contents = update_report_contents(report_contents, "potential_os_installation_date.txt", folder_location, section_sub_title="Host Installation Details", section_description="Potential date on which the host was installed")

    ### Static IP Addresses
    report_contents = update_report_contents(report_contents, "static_ip_addresses.txt", folder_location, section_title="Static IP Addresses", section_description="The static IP addresses on the machine. The output is from the /etc/hosts file in linux")

    ### Active Connections
    report_contents = add_header(report_contents, "Active Connections")

    report_contents = update_report_contents(report_contents, "active_connections_netstat.txt", folder_location, section_title="", section_sub_title="Netstat", section_description="Current active connections found using netstat command.")

    report_contents = update_report_contents(report_contents, "active_connections_ss.txt", folder_location, section_title="", section_sub_title="SS", section_description="Ports the machine is listening on. Found using ss command.")
    
    ### Running process
    report_contents = update_report_contents(report_contents, "running_processes.txt", folder_location, section_title="Currently running process", section_description="Shows the current running processes and the user that initiated that process")
    

    ### Users on the system
    report_contents = update_report_contents(report_contents, "users.txt", folder_location, section_title="Users on the system", section_description="All the users on the system that are either in /home directory or can execute /bin/bash to SSH")

    ### All users on system
    report_contents = update_report_contents(report_contents, "users_all.txt", folder_location, section_title="All users on the system", section_description="All the users found in /etc/passwd file. An attacker might create an account. Read about it here: https://attack.mitre.org/techniques/T1136/")

    ### Users with SUID bit set to 0
    report_contents = update_report_contents(report_contents, "users_suid_eq_0.txt", folder_location, section_title="", section_sub_title="Users with ID set to 0", section_description="Users that have ID set to 0 in /etc/passwd. This is a possibile backdoor mechanism as users with ID set to 0 can execute command as root")

    ### Users who can run sudo
    report_contents = update_report_contents(report_contents, "users_sudo.txt", folder_location, section_title="", section_sub_title="Users who can run sudo", section_description="Users who are in the sudo group. Found and associated groups found in /etc/group")

    ### Commands that users can run as sudo
    report_contents = update_report_contents(report_contents, "users_sudo_list.txt", folder_location, section_title="", section_sub_title="Commands that users can run as sudo", section_description="Commands a user can run as sudo. These commands are found in /etc/sudoers.d/ folder. Read more about it here: https://attack.mitre.org/techniques/T1548/003/")

 
    ### Bash history of the users
    report_contents = add_header(report_contents, "User data")

    
    users = []
    try:
        with open("{}/users.txt".format(folder_location), "r") as f:
            users = f.read().split("\n")

    except FileNotFoundError as e:
            print("Ran into error while opening the file at {}/{}. Error: {}".format(folder_location, "users.txt", e))

    for user in users:
        if user == "":
            continue

        report_contents += "\n### {}".format(user)

        ### Bash history
        report_contents = update_report_contents(report_contents, "{0}/bash_history_{0}.txt".format(user), folder_location, section_title="", section_sub_title="Bash History", section_description="Bash History of the user")

        ### SSH files
        report_contents = update_report_contents(report_contents, "{}/ssh_files/authorized_keys".format(user), folder_location, section_title="", section_sub_title="SSH Files - authorized_keys output", section_description="Dumps out contents of authorized_keys. Possible backdoor mechanism where an attacker might dump the public key in this file and save the private key on their system to maintain persistence. Read more about it here: https://attack.mitre.org/techniques/T1098/004/")

        ### Browsing History
        report_contents = update_report_contents(report_contents, "{}/firefox_data/browsing_history/firefox_browsing_history.txt".format(user), folder_location, section_title="", section_sub_title="Web Browsing History - Firefox", section_description="Browsing History of the user. Shows time and the website visited. Time is in UNIX format")


    ### Logs
    report_contents = add_header(report_contents, "Logs")

    report_contents = update_report_contents(report_contents, "logs/auth_commands.log", folder_location, section_title="", section_sub_title="Commands run as sudo", section_description="All the commands run as sudo are logged in auth.log file. Here are the cleaned out contents and commands ran")

    report_contents = update_report_contents(report_contents, "logs/wtmp_logs.txt", folder_location, section_title="", section_sub_title="WTMP logs", section_description="wtmp acts as a historical utmp.")

    # report_contents = update_report_contents(report_contents, "logs/btmp_logs.txt", folder_location, section_title="", section_sub_title="BTMP logs")

    report_contents = update_report_contents(report_contents, "logs/utmp_logs.txt", folder_location, section_title="", section_sub_title="UTMP logs", section_description="utmp maintains a full accounting of the current status of the system, system boot time (used by uptime), recording user logins at which terminals, logouts, system events etc.")

    report_contents += "\n*Note: You can also find all the bad login attempts under btmp logs. It should be located in {}/btmp*\n".format(folder_location)

    ### Other stats

    report_contents = add_header(report_contents, "Other stats!")

    report_contents = update_report_contents(report_contents, "users_loggedon.txt", folder_location, section_title="", section_sub_title="Users Logged On", section_description="Current users logged on the system.")

    report_contents = update_report_contents(report_contents, "users_loggedon_moreinfo.txt", folder_location, section_title="", section_sub_title="Users Logged On - More Info")

    ### Cron Jobs
    report_contents = add_header(report_contents, "Scheduled Tasks - Cronjobs")

    report_contents += "\n*Cron jobs can serve as a persistence mechanism when configured to periodically send a reverse shell back to your attacker machine. Read more about it here: https://attack.mitre.org/techniques/T1053/003/*\n"

    for user in users:
        if user == "":
            continue
        report_contents = update_report_contents(report_contents, "list_scheduled_tasks_crontab_{}.txt".format(user), folder_location, section_title="", section_sub_title="Cronjob for user - {}".format(user))
    
    report_contents = update_report_contents(report_contents, "list_cronjobs.txt", folder_location, section_title="", section_sub_title="Crontabs")

    report_contents = update_report_contents(report_contents, "listed_user_cronjobs.txt", folder_location, section_title="", section_sub_title="Crontabs for a listed user")

    report_contents = update_report_contents(report_contents, "listed_cron.d.txt", folder_location, section_title="", section_sub_title="cron.d")

    report_contents = update_report_contents(report_contents, "listed_cron.daily.txt", folder_location, section_title="", section_sub_title="cron.daily")

    report_contents = update_report_contents(report_contents, "listed_cron.hourly.txt", folder_location, section_title="", section_sub_title="cron.hourly")

    report_contents = update_report_contents(report_contents, "listed_cron.hourly.txt", folder_location, section_title="", section_sub_title="cron.weekly")


    report_contents = add_header(report_contents, "Other interesting files")

    report_contents = update_report_contents(report_contents, "startup_files_initd_recently_modified.txt", folder_location, section_title="", section_sub_title="Files modified in init.d", section_description="Services of init.d start on startup. The backdoor can be added as a system service that is launched at startup. Read more about it here: https://attack.mitre.org/techniques/T1037/")

    report_contents = update_report_contents(report_contents, "startup_files_systemd_recently_modified.txt", folder_location, section_title="", section_sub_title="Files modified in systemd", section_description="Services of systemd start on startup. The backdoor can be added as a system service that is launched at startup. Read more about it here: https://attack.mitre.org/techniques/T1543/002/")

    report_contents = update_report_contents(report_contents, "files_owned_by_root.txt", folder_location, section_title="", section_sub_title="Files owned by user root", section_description="See the files owned by root and if any of them leave you open to a privilege escalation attack.")

    report_contents = update_report_contents(report_contents, "files_sgid.txt", folder_location, section_title="", section_sub_title="Checks for SGID files", section_description="SGID files can be used to perform privilege escalation attacks. Read more about it here: https://attack.mitre.org/techniques/T1548/001/")

    # report_contents = update_report_contents(report_contents, "files_updated_recently.txt", folder_location, section_title="", section_sub_title="Checks for files updated within last 7 days")
    
    report_contents = update_report_contents(report_contents, "tmp_directory_list.txt", folder_location, section_title="", section_sub_title="Files in /tmp directory", section_description="Attacker might store the malware or run a program that creates files in /tmp location.")


    with open("{}.md".format(report_title), "w+") as f:
        f.write(report_contents)
        print("Created output file: {}.md".format(report_title))

    upload_report("{}.md".format(report_title), report_title)

# create_md_file("auto_script_output", "Incident Response")
if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="report_generator.py", 
                                    description="A Python script to upload the output folder of auto.sh to your Notion workspace",
                                    usage='%(prog)s -f <files to be uploaded> -t <Report Title>')
    parser.add_argument("-f", "--tarlocation", help="Tar location", required=True)
    parser.add_argument("-t", "--title", help="Report Title", required=True)
    arguments = parser.parse_args()

    tar_file = tarfile.open(arguments.tarlocation)
    folder_location = arguments.tarlocation.split(".")[0]
    tar_file.extractall("./{}".format(folder_location))

    create_md_file("{0}/{0}".format(folder_location), arguments.title)