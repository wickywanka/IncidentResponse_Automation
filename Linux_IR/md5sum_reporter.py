#!/usr/bin/env python3

import requests, time, json, argparse

hashes_file = {}



with open("config.json", "r") as f:
    config = json.loads(f.read())

def process_hashes(folder_location):
    try:
        with open("{0}/{0}/hashes_of_all_files.txt".format(folder_location), "r") as f:
            hashes_list = f.read().split("\n")
    except:
        return

    vtkeys = config["virustotal_api_keys"]
    vt_key_counter = 0
    
    for hashes in hashes_list:
        hash = hashes.split("  ")[0]
        file_location = hashes.split("  ")[-1]
        params = {'apikey': vtkeys[vt_key_counter], 'resource': hash}
        headers = {"User-Agent" : "User-Agent': 'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.14 (KHTML, like Gecko) Chrome/24.0.1292.0 Safari/537.14"}
        r = requests.get('https://www.virustotal.com/vtapi/v2/file/report',params=params, headers=headers)
        data = r.json()
        vt_key_counter += 1
        vt_key_counter = vt_key_counter % len(vtkeys)
        if data['response_code'] == 1:
            positives = data['positives']
            total = data['total']
            print ("Detection Ratio: {}/{} for {}".format(positives,total, file_location))
        else:
            print ("No records on VirusTotal for {}".format(file_location))
        time.sleep(16//len(vtkeys))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="md5sum_reporter.py", 
                                    description="A Python script to upload hashes and state detection rate",
                                    usage='%(prog)s -f <folder location>')
    parser.add_argument("-f", "--folderlocation", help="Folder location", required=True)
    arguments = parser.parse_args()
    process_hashes(arguments.folderlocation)