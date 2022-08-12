# IncidentResponse_Automation

If you want to read about the project which me and my team have developed, give the project report a read which I have uploaded.
It explains all the functioning of the project, along with the motivation, background, and future scope of the project.

A new thought popped in my head regarding writing a script for Automating Incident Resonse process for Linux systems. You can see I have made a new folder named *Linux_IR* where I have uploaded the scripts.

Now this simple script aims to automate early stages of an incident response for Linux based systems. This works for both live systems or if you have a Linux drive mounted on your system.


## Usage
Run the script using bash as a root user:
```bash
$ ./auto.sh [-o OUTPUT_DIR -m MOUNT_LOCATION]
```

Example: 
```bash
$ ./auto.sh -o auto_script_output
$ ./auto.sh -o auto_script_output -m /mnt/mydisk # if you have a disk mounted at /mnt/mydisk
```

**For Python script report_generator.py**

Upload to output of the script to automatically generate a report on Notion:
```bash
$ ./report_generator.py -f <Input folder location> -t <Report Title>
$ ./report_generator.py -f auto_script_output -t "My Incidient Response"
``` 

My plan is to initialize these scripts with AWS so that I can automate Incident Response Process for Linux Systems and give a detailed report on what was exactly happening on the system. 

Any inputs are appreciated :)