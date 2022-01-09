#!/usr/bin/env python3
__author__ = "ScherifMark"

import argparse
import datetime
import io
import json
import re
import zipfile
from argparse import RawTextHelpFormatter
from urllib.parse import urlparse, parse_qs, quote_plus, unquote
from xml.dom import minidom
import requests
import xlsxwriter
from cpe import CPE
from tqdm import tqdm

ERROR_STRING = "-"
cwe_dict = {'CWE-noinfo': '', 'CWE-Other': ''}
cwe_xml_path = ""


def get_exploit_db(cve):
	"""
	Lookup exploitDB entries for CVE
	@param cve: sting of CVE name
	@return: string with expoitDB IDs separated with " | "
	"""
	get_header = {
		'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36',
		'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest'}
	r = requests.get("https://www.exploit-db.com/search?cve=" + get_id(cve), headers=get_header)
	ids_str = ""
	if r.status_code == 200:
		exploits = json.loads(r.text)['data']
		separator = ""
		for e in exploits:
			ids_str += separator + str(e['id'])
			separator = " | "
	else:
		ids_str = "Code " + str(r.status_code)
	return ids_str


def get_cwe_name():
	"""
	Download list of all CWEs and store it in a dict {cwe_id:cwe_name}
	"""
	print("Downloading and processing CWE List")
	get_header = {
		'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}
	r = requests.get("https://cwe.mitre.org/data/xml/cwec_latest.xml.zip", headers=get_header)
	zipObj = zipfile.ZipFile(io.BytesIO(r.content))
	filename = zipObj.namelist()[0]
	test = zipObj.read(filename).decode("utf-8")
	xmldoc = minidom.parseString(test)
	itemlist = xmldoc.getElementsByTagName('Weakness')
	for cwe in itemlist:
		cwe_dict[cwe.attributes['ID'].value] = cwe.attributes['Name'].value


def get_id(cve):
	"""
	Return CVE id
	@param cve: CVE object
	@return: string with CVE id
	"""
	try:
		return cve['cve']['CVE_data_meta']['ID']
	except:
		return ERROR_STRING


def get_cvss2_score(cve):
	"""
	Return CVE's CVSSv2 score
	@param cve: CVE object
	@return: string with CVE's CVSSv2 score
	"""
	try:
		return cve['impact']['baseMetricV2']['cvssV2']['baseScore']
	except:
		return ERROR_STRING


def get_cvss3_score(cve):
	"""
	Return CVE's CVSSv3 score
	@param cve: CVE object
	@return: string with CVE's CVSSv3 score
	"""
	try:
		return cve['impact']['baseMetricV3']['cvssV3']['baseScore']
	except:
		return ERROR_STRING


def get_cvss3_vector(cve):
	"""
	Return CVE's CVSSv3 vector
	@param cve: CVE object
	@return: string with CVE's CVSSv3 vector
	"""
	try:
		return cve['impact']['baseMetricV3']['cvssV3']["vectorString"]
	except:
		return ERROR_STRING


def get_pub_date(cve):
	"""
	Return CVE's publishing date
	@param cve: CVE object
	@return: string with CVE's publishing date
	"""
	try:
		return cve['publishedDate'][:10]
	except:
		return ERROR_STRING


def get_description(cve):
	"""
	Return CVE description
	@param cve: CVE object
	@return: string with CVE description
	"""
	try:
		desc = ""
		for description in cve['cve']['description']['description_data']:
			desc += description['value']
		return desc
	except:
		return ERROR_STRING


def get_cwe(cve):
	"""
	Return CVE's CWE category
	@param cve: CVE object
	@return: string with CVE's CWE category
	"""
	cwe = cve['cve']['problemtype']['problemtype_data'][0]['description'][0]['value']
	try:
		cwe_desc = cwe + ":" + cwe_dict[cwe[4:]]
	except:
		cwe_desc = cwe
	return cwe, cwe_desc


def get_access(cve):
	"""
	Return CVE's Access vecor (CVSSv2)
	@param cve: CVE object
	@return: string with CVE's Access vecor (CVSSv2)
	"""
	try:
		return cve['impact']['baseMetricV2']['cvssV2']['accessVector']
	except:
		return ERROR_STRING


def get_complexity(cve):
	"""
	Return CVE's complexity vecor (CVSSv2)
	@param cve: CVE object
	@return: string with CVE's complexity vecor (CVSSv2)
	"""
	try:
		return cve['impact']['baseMetricV2']['cvssV2']['accessComplexity']
	except:
		return ERROR_STRING


def get_cves_list(cpe):
	"""
	Return a list off all CVEs that are registered for the CPE/product
	@param cve: CVE object
	@return: list off all CVEs that are registered for the CPE/product - CVE objects
	"""
	cves = []
	startIndex = 0
	remaining = 1
	while remaining > 0:
		response = requests.get(
			"https://services.nvd.nist.gov/rest/json/cves/1.0?resultsPerPage=2000&cpeMatchString=%s&startIndex=%s" % (
				cpe, str(startIndex)))
		results = json.loads(response.text)
		cves += results['result']['CVE_Items']
		startIndex += 2000
		remaining = results['totalResults'] - startIndex

	cves = sorted(cves, key=lambda d: d['impact']['baseMetricV2']['cvssV2']['baseScore'],
				  reverse=True)
	return cves


def process_input(line):
	"""
	Extract CPE from NIST search URL/given CPE/keywords
	@param line: NIST search URL/given CPE/keywords
	@return: CPE object
	"""
	if (line[:4] == "http"):
		try:
			url = line
			parsed_url = urlparse(url)
			params_parsed = parse_qs(parsed_url.query)
			found = False
			for p in ['cpe_version', 'cpe_product', 'cpe_vendor']:
				if p in params_parsed:
					line = params_parsed[p][0]
					found = True
					break
			if not found:
				print(" - could not be parsed")
				return ERROR_STRING
		except:
			print(" - could not be parsed")
			return ERROR_STRING

	search_value = "keyword"

	if line[:4] == "cpe:":
		search_value = "cpeMatchString"
	else:  # keyword
		if len(line) < 3 or len(line) > 512:
			print("keyword: size must be between 3 and 512")
			return ERROR_STRING

	cpes = []
	startIndex = 0
	remaining = 1
	while remaining > 0:
		response = requests.get(
			"https://services.nvd.nist.gov/rest/json/cpes/1.0?resultsPerPage=2000&%s=%s&startIndex=%s" % (search_value,
																										  quote_plus(
																											  line),
																										  str(startIndex)))
		results = json.loads(response.text)
		cpes += results['result']['cpes']
		startIndex += 2000
		remaining = results['totalResults'] - startIndex

	if (len(cpes) == 0):
		print("Could not find any CPEs for %s" % (line))
		return ERROR_STRING
	elif (len(cpes) == 1):
		return cpes[0]
	print("Select CPE for %s:" % (line))

	for c in range(0, len(cpes)):
		print("[%d] %s \t %s" % (c, cpes[c]['cpe23Uri'], cpes[c]['titles'][0]['title']))
	select = -1
	while not (select >= 0 and select < len(cpes)):
		select = int(input("Select CPE: "))
	return cpes[select]


def get_worksheet_titel(cpe_string):
	"""
	Generate title based on CPE string
	@param cpe_string: CPE string
	@return: title string
	"""
	cpe = CPE(unquote(cpe_string))
	title = ""
	if str(cpe.get_vendor()[0]) != "":
		title += str(cpe.get_vendor()[0])
	if str(cpe.get_product()[0]) != "":
		title += "_" + str(cpe.get_product()[0])
	if str(cpe.get_version()[0]) != "":
		title += "_" + str(cpe.get_version()[0])
	return title


def get_product(cpe_string):
	"""
	Extract product name from CPE string
	@param cpe_string: CPE string
	@return: product name string
	"""
	cpe = CPE(unquote(cpe_string))
	title = ""
	if str(cpe.get_vendor()[0]) != "":
		title += str(cpe.get_vendor()[0])
	if str(cpe.get_product()[0]) != "":
		title += " " + str(cpe.get_product()[0])
	return title


if __name__ == '__main__':
	parser = argparse.ArgumentParser(
		description="Go to https://nvd.nist.gov/vuln/search -> Advanced \nSearch for the software\nEither copy the cpe String or click 'Search' and copy the link\n\nCopy the cpe/link to a file (cvelist) or use it as input (cpes)\n\nOutput: CVE Table for related vulnerabilities (outfile [default:cves.xlsx])",
		formatter_class=RawTextHelpFormatter)
	parser.add_argument('-o', '--outfile', metavar='outfile', nargs='?', default="cves.xlsx",
						help='File where CVE Tables are written to')
	parser.add_argument('-l', '--list', nargs='*',
						help='File with cpe/links')
	parser.add_argument('-p', '--products', nargs='*',
						help='cpe/link')
	parser.add_argument('-n', '--noexploits', action='store_true', default=False,
						help="Don't lookup exploits")
	args = parser.parse_args()

	products = args.products
	if args.products:
		products = args.products
	else:
		products = []
	if (args.list):
		for file in args.list:
			with open(file) as f:
				lines = f.readlines()
				for l in lines:
					if l[0] != "#" and len(l) > 1:
						if (re.findall(r'^(\s+\n+)$', l, re.M)):
							continue
						l = re.search(r'^\s*(.*[^\s])[\s\n]*$', l, re.M).group(1)
						products.append(l)

	# convert to cpe
	product_cpes = []
	for p in products:
		cpe = process_input(p)
		if (cpe != ERROR_STRING):
			product_cpes.append(cpe)

	##### process CPEs and write CVEs to file
	filename = args.outfile
	search_exploits = not args.noexploits
	get_cwe_name()
	workbook = xlsxwriter.Workbook(filename)
	bold = workbook.add_format({'bold': True})
	link_count = 0

	number_format = workbook.add_format({'num_format': '0.0'})
	date_format = workbook.add_format({'num_format': 'YYYY-MM-DD'})
	wrap_format = workbook.add_format()
	wrap_format.set_text_wrap()

	for cpe in product_cpes:
		link_count += 1
		cpe_string = cpe['cpe23Uri']
		title = cpe['titles'][0]['title']
		print("Processing: " + title)
		try:
			if cpe == "":
				continue

			worksheet = workbook.add_worksheet(str(link_count) + "_" + get_worksheet_titel(cpe_string))
			cves = get_cves_list(cpe_string)
			worksheet.write(0, 0, title, bold)
			worksheet.write(1, 0, unquote(cpe_string))
			worksheet.write_url(2, 0,
								"https://www.google.com/search?q=" + quote_plus(
									get_product(cpe_string) + " latest release"),
								string="Search for latest Version")
			row = 5
			col = 0
			if len(cves) == 0:
				continue
			for cve in tqdm(cves):
				cve_id = str(get_id(cve))
				col = 0
				worksheet.write_url(row, col, "https://nvd.nist.gov/vuln/detail/" + cve_id, string=cve_id)
				col += 1
				cwe, cwe_str = get_cwe(cve)
				if cwe not in ['NVD-CWE-noinfo', 'NVD-CWE-Other']:
					worksheet.write_url(row, col, "https://cwe.mitre.org/data/definitions/" + str(cwe)[4:],
										string=str(cwe_str))
				else:
					worksheet.write_string(row, col, str(cwe_str))
				col += 1
				date_time = datetime.datetime.strptime(str(get_pub_date(cve)), '%Y-%m-%d')
				worksheet.write_datetime(row, col, date_time, date_format)
				col += 1
				worksheet.write_number(row, col, float(str(get_cvss2_score(cve))), number_format)
				col += 1
				worksheet.write_string(row, col, str(get_access(cve)).title())
				col += 1
				worksheet.write_string(row, col, str(get_complexity(cve)).title())
				col += 1
				try:
					worksheet.write_number(row, col, float(str(get_cvss3_score(cve))), number_format)
				except:
					worksheet.write(row, col, "")
				col += 1
				cvssvector = str(get_cvss3_vector(cve))
				if cvssvector != ERROR_STRING:
					worksheet.write_url(row, col, "https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?name=" + cve_id,
										string=cvssvector)
				col += 1

				if search_exploits and str(CPE(unquote(cpe_string)).get_product()[0]) != "":
					exploit_ids = str(get_exploit_db(cve))
					if exploit_ids != "":
						if "|" in exploit_ids:
							worksheet.write_url(row, col, "https://www.exploit-db.com/search?cve=" + get_id(cve),
												string=exploit_ids)
						else:
							worksheet.write_url(row, col, "https://www.exploit-db.com/exploits/" + exploit_ids,
												string=exploit_ids)
				col += 1
				worksheet.write_string(row, col, str(get_description(cve)), wrap_format)
				row += 1
			cells = "A5:" + chr(65 + col) + str(len(cves) + 5)
			worksheet.add_table(cells, {'columns': [{'header': 'CVE-ID'},
													{'header': 'Vulnerability Type'},
													{'header': 'Publish Date'},
													{'header': 'Score (2.0)'},
													{'header': 'Access'},
													{'header': 'Complexity'},
													{'header': 'Score (3.1)'},
													{'header': 'Vector (3.1)'},
													{'header': 'ExploitDB IDs'},
													{'header': 'Description'},
													{'header': 'Score (2.0) [Sort]'},
													{'header': 'Score (3.1) [Sort]'},
													]})
			# Light red fill with dark red text if CVE is disputed
			format1 = workbook.add_format({'bg_color': '#FFC7CE',
										   'font_color': '#9C0006'})
			worksheet.conditional_format(cells, {'type': 'formula',
												 'criteria': '=ISNUMBER(SEARCH("** DISPUTED **",$J5))',
												 'format': format1})
			column_width = [15, 18, 13, 10, 15, 12, 10, 37, 13, 250]
			for i in range(0, len(column_width)):
				worksheet.set_column(i, i, column_width[i])
		except IndexError:
			print("ERROR")

	print("Your XLXS file has been successfully generated: %s" % filename)
	workbook.close()
