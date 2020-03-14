import json
import requests
import tldextract

from queue import Queue
from time import sleep
from datetime import datetime
from fake_useragent import UserAgent
from concurrent.futures import ThreadPoolExecutor

# from recursivejson import extract_values


def extract_values(obj, key):
    """Pull all values of specified key from nested JSON."""
    arr = []

    def extract(obj, arr, key):
        """Recursively search for values of key in JSON tree."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    extract(v, arr, key)
                elif k == key:
                    arr.append(v)
        elif isinstance(obj, list):
            for item in obj:
                extract(item, arr, key)
        return arr

    results = extract(obj, arr, key)
    return results


def get_domains_from_webarchive(KEYWORDS_Q, KEYWORDS_Q_LEN, DOMAINS_Q):
	while True:
		# check queue
		if KEYWORDS_Q.empty():
			sleep(5)
			if KEYWORDS_Q.empty():
				print('queue is empty')
				tex = 'tex'
				return tex

		query = KEYWORDS_Q.get()
		q_len_now = KEYWORDS_Q.qsize()

		api_url = 'http://web.archive.org/__wb/search/anchor?q='+query

		try:
			r = requests.get(api_url)

			json_data = r.json()
			domains = extract_values(json_data, 'name')

			for host in domains:
				ext = tldextract.extract(host)
				domain = ext.domain+'.'+ext.suffix
				DOMAINS_SET.add(domain)

			print_result = "[ {} / {} ] ## {}".format(q_len_now, KEYWORDS_Q_LEN, query)
			print(print_result)

		except Exception as e0:
		    print("API request error: {error}".format(error=e0))


def get_domain_available_status(urls_q, result_file, ua, Q_LEN):
	while True:
		# check queue
		if urls_q.empty():
			sleep(5)
			print('sleep')
			if urls_q.empty():
				print('queue is empty')
				return tex
		try:
			domain = urls_q.get()

			headers = {
			    'User-Agent': ua.chrome,
			    'x-requested-with': 'XMLHttpRequest',
			}

			url = 'https://panel.dreamhost.com/marketing/ajax.cgi?cmd=domreg-availability&domain='+ domain +'&pricing_wanted=1'
			r = requests.get(url, headers=headers)
			available_status = r.json()['available']
			
			result_data = "{},{}\n".format(domain,available_status)
			result_file.write(result_data)
			q_len_now = urls_q.qsize()

			print('[',str(q_len_now), ' / ',str(Q_LEN),'] ## ',str(available_status),' ##', domain)

		except Exception as error:
			print('Error: for', domain, ' ## ', str(error), str(type(error)))

startTime = datetime.now()
KEYWORDS_Q = Queue() # queue for keywords
DOMAINS_Q = Queue()  # queue for domains
DOMAINS_SET = set()  # set for uniq domains from webarchive
urls_q = Queue()     # queue for check available status by domain.com 

with open('keywords.txt', 'r', encoding='utf-8') as keywords_file:
	for key in keywords_file:
		key = key.replace('\n','')
		KEYWORDS_Q.put(key)


KEYWORDS_Q_LEN = KEYWORDS_Q.qsize()
	
threads = 5 # count of threads for webarchive

with ThreadPoolExecutor(max_workers=threads) as ex:
	for _ in range(threads):
		ex.submit(get_domains_from_webarchive, KEYWORDS_Q, KEYWORDS_Q_LEN, DOMAINS_SET)

print('done!!')


with open('domains-result.csv', 'w', encoding='utf-8') as domains_result_file:
	for domain in DOMAINS_SET:
		domains_result_file.write(domain+'\n')
		print(domain)


# run check available status by domain.com
ua = UserAgent()

for domain in DOMAINS_SET:
	urls_q.put(domain)
	Q_LEN = urls_q.qsize()

threads = 10 # count of threads for domain.com

with open('result.csv', 'w', encoding='UTF-8') as result_file:
	result_file.write('domain,available_status\n')
	with ThreadPoolExecutor(max_workers=threads) as ex:
		for _ in range(threads):
			ex.submit(get_domain_available_status, urls_q, result_file, ua, Q_LEN)

print('Work time: ', datetime.now() - startTime)



