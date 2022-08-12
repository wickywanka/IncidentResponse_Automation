#!/usr/bin/env python3

import requests
import json
import requests, time, json, argparse


with open("config.json", "r") as f:
    config = json.loads(f.read())

def process_urls(folder_location):
	try:
		with open("{0}/{0}/users.txt".format(folder_location), "r") as f:
			users = f.read().split("\n")
	except:
		return
	
	vtkeys = config["virustotal_api_keys"]
	vt_key_counter = 0
	for user in users:
		if user == "":
			continue
		try:
			with open("{0}/{0}/{1}/firefox_data/browsing_history/firefox_browsing_history.txt".format(folder_location, user)) as f:
				urls = f.read().split("\n")
		except:
			print("No records found for user: {}".format(user))
			continue

		for url in urls:
			if url == "":
				continue
			extracted_url = url.split("|")[-1]
			params = {'apikey': vtkeys[vt_key_counter], 'resource': extracted_url}
			headers = {"User-Agent" : "User-Agent': 'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.14 (KHTML, like Gecko) Chrome/24.0.1292.0 Safari/537.14"}
			r = requests.get('https://www.virustotal.com/vtapi/v2/url/report',params=params, headers=headers)
			data = r.json()
			vt_key_counter += 1
			vt_key_counter = vt_key_counter % len(vtkeys)
			if data['response_code'] == 1:
				positives = data['positives']
				total = data['total']
				print ("Detection Ratio: {}/{} for {}".format(positives,total, extracted_url))
			else:
				print ("No records on VirusTotal for {}".format(extracted_url))
			time.sleep(16//len(vtkeys))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="url_reporter.py", 
                                    description="A Python script to upload hashes and state detection rate",
                                    usage='%(prog)s -f <folder location>')
    parser.add_argument("-f", "--folderlocation", help="Folder location", required=True)
    arguments = parser.parse_args()
    process_urls(arguments.folderlocation)

	            