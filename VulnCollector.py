#!/usr/bin/env python3
__author__ = "ScherifMark"

import argparse
import datetime
import io
import json
import re
import urllib.parse
import zipfile
from argparse import RawTextHelpFormatter
from urllib.parse import urlparse, parse_qs, quote_plus, unquote
from xml.dom import minidom
import requests
import xlsxwriter
from cpe import CPE
from tqdm import tqdm
from enum import Enum

ERROR_STRING = "-"
cwe_dict = {'CWE-noinfo': '', 'CWE-Other': ''}
exploit_id_cache = {}
exploit_reference_count_cache = {}

class Coloring(Enum):
	coloring_off = 'OFF'
	coloring_cvssv2 = 'CVSSv2'
	coloring_cvssv3 = 'CVSSv3'

	def __str__(self):
		return self.value

def get_exploit_db(cve):
	"""
	Lookup exploitDB entries for CVE
	@param cve: sting of CVE name
	@return: string with expoitDB IDs separated with " | "
	"""
	ids_str = ""
	cve_id = get_id(cve)
	if cve_id in exploit_id_cache:
		return exploit_id_cache[cve_id]
	try:
		get_header = {
			'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36',
			'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest'}
		r = requests.get("https://www.exploit-db.com/search?cve=" + cve_id, headers=get_header)
		if r.status_code == 200:
			exploits = json.loads(r.text)['data']
			separator = ""
			for e in exploits:
				ids_str += separator + str(e['id'])
				separator = " | "
		exploit_id_cache[cve_id] = ids_str
		#else:
		#	ids_str = "Code " + str(r.status_code)
	except requests.exceptions.RequestException:
		ids_str = "Connection Error"
	return ids_str


def get_cwe_name():
	"""
	Download list of all CWEs and store it in a dict {cwe_id:cwe_name}
	"""
	print("Downloading and processing CWE List")
	get_header = {
		'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}
	try:
		r = requests.get("https://cwe.mitre.org/data/xml/cwec_latest.xml.zip", headers=get_header)
		zipObj = zipfile.ZipFile(io.BytesIO(r.content))
		filename = zipObj.namelist()[0]
		test = zipObj.read(filename).decode("utf-8")
		xmldoc = minidom.parseString(test)
		itemlist = xmldoc.getElementsByTagName('Weakness')
		for cwe in itemlist:
			cwe_dict[cwe.attributes['ID'].value] = cwe.attributes['Name'].value
	except requests.exceptions.RequestException:
		print("Connection error while requesting CWE Names")


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
		if get_exploit_reference_count(cve) > 0:
			desc += "\n+++Exploit References availible!+++"
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

def get_exploit_reference_count(cve):
	"""
	Return the number of references to exploits
	@param cve: CVE object
	@return: number of references that include an exploit
	"""
	cve_id = get_id(cve)
	if cve_id in exploit_reference_count_cache:
		return exploit_reference_count_cache[cve_id]
	count = 0
	for reference in cve['cve']['references']['reference_data']:
		if("Exploit" in reference['tags']):
			count +=1
	exploit_reference_count_cache[cve_id] = count
	return count

def get_cves_list(cpe):
	"""
	Return a list off all CVEs that are registered for the CPE/product
	@param cve: CVE object
	@return: list off all CVEs that are registered for the CPE/product - CVE objects
	"""
	cves = []
	try:
		startIndex = 0
		remaining = 1
		while remaining > 0:
			response = requests.get(
				"https://services.nvd.nist.gov/rest/json/cves/1.0?resultsPerPage=2000&cpeName=%s&startIndex=%s" % (
					urllib.parse.quote(cpe), str(startIndex)))
			results = json.loads(response.text)
			cves += results['result']['CVE_Items']
			startIndex += 2000
			remaining = results['totalResults'] - startIndex

		cves = sorted(cves, key=lambda d: d['impact']['baseMetricV2']['cvssV2']['baseScore'],
					  reverse=True)
	except requests.exceptions.RequestException:
		print("Connection error while getting vulnerabilites for "+cpe)
	return cves


def process_input(product):
	"""
	Extract CPE from NIST search URL/given CPE/keywords
	@param product: NIST search URL/given CPE/keywords
	@return: array of CPE objects
	"""
	if (product[:4] == "http"):
		try:
			url = product
			parsed_url = urlparse(url)
			params_parsed = parse_qs(parsed_url.query)
			found = False
			for p in ['cpe_version', 'cpe_product', 'cpe_vendor']:
				if p in params_parsed:
					product = params_parsed[p][0]
					found = True
					break
			if not found:
				print(" - could not be parsed")
				return []
		except:
			print(" - could not be parsed")
			return []

	search_value = "keyword"

	if product[:4] == "cpe:":
		search_value = "cpeMatchString"
	else:  # keyword
		if len(product) < 3 or len(product) > 512:
			print("keyword: size must be between 3 and 512")
			return []

	cpes = []
	try:
		startIndex = 0
		remaining = 1
		while remaining > 0:
			response = requests.get(
				"https://services.nvd.nist.gov/rest/json/cpes/1.0?resultsPerPage=2000&%s=%s&startIndex=%s" % (search_value,
																											  quote_plus(
																												  product),
																											  str(startIndex)))
			results = json.loads(response.text)
			cpes += results['result']['cpes']
			startIndex += 2000
			remaining = results['totalResults'] - startIndex
	except requests.exceptions.RequestException:
		print("Connection error during CPE lookup for %s" % (product))
	if (len(cpes) == 0):
		if(".js" in product): # js library cpe information sometimes does not contain .js and are therefore not found
			print("Could not find any CPEs for %s" % (product))
			product = product.replace(".js","") # remove .js to make search more general
			print(f"\tTrying {product}")
			return process_input(product)
		print("Could not find any CPEs for %s" % (product))
		return []
	elif (len(cpes) == 1):
		return [cpes[0]]
	print("Select CPE for %s:" % (product))

	for c in range(0, len(cpes)):
		print("[%d] %s \t %s" % (c, cpes[c]['cpe23Uri'], cpes[c]['titles'][0]['title']))
	print("[%s] %s" % ("A", "All"))
	print("[%s] %s" % ("N", "None"))
	select = -1
	selected_cpes = []
	while not (select != -1):
		user_selection = input("Select CPE: ")
		split_user_selection = user_selection.split()
		if len(split_user_selection) == 1 and split_user_selection[0].upper() == "N":
			return []
		if len(split_user_selection) == 1 and split_user_selection[0].upper() == "A":
			return cpes
		for sel in split_user_selection:
			sel = int(sel)
			if (sel >= 0 and sel < len(cpes)):
				selected_cpes.append(cpes[sel])
				select += 1
	return selected_cpes


def get_worksheet_titel(prefix,cpe_uri):
	"""
	Generate title based on CPE string
	@param cpe_uri: CPE string
	@return: title string
	"""
	cpe = CPE(unquote(cpe_uri))
	title = ""
	if str(cpe.get_vendor()[0]) != "":
		title += str(cpe.get_vendor()[0])
	if str(cpe.get_product()[0]) != "":
		title += "_" + str(cpe.get_product()[0])
	if str(cpe.get_version()[0]) != "":
		title += "_" + str(cpe.get_version()[0])
	if len(title)+len(prefix)>31:
		title=title[len(title)+len(prefix)-31:]
	return prefix+title


def get_product(cpe_uri):
	"""
	Extract product name from CPE string
	@param cpe_uri: CPE string
	@return: product name string
	"""
	cpe = CPE(unquote(cpe_uri))
	title = ""
	if str(cpe.get_vendor()[0]) != "":
		title += str(cpe.get_vendor()[0])
	if str(cpe.get_product()[0]) != "":
		title += " " + str(cpe.get_product()[0])
	return title



if __name__ == '__main__':
	print("This product uses the NVD API but is not endorsed or certified by the NVD.")
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
	parser.add_argument('--nocharts', action='store_true', default=False,
						help="Don't insert CVSSv2 and CVSSv3 charts")
	parser.add_argument('--coloring', type=Coloring, choices=list(Coloring), default='CVSSv2',
						help="Choose default coloring option")
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
				if file[-4:] == ".xml" and lines[1] == '<!DOCTYPE nmaprun>\n':  # nmap xml
					nmap_cpes = re.findall(r"<cpe>([^<]*)<\/cpe>", "\n".join([l.rstrip() for l in lines]))
					products += nmap_cpes
					continue
				for l in lines:
					if l[0] != "#" and len(l) > 1:
						if (re.findall(r'^(\s+\n+)$', l, re.M)):
							continue
						l = re.search(r'^\s*(.*[^\s])[\s\n]*$', l, re.M).group(1)
						products.append(l)

	products = list(set(products))  # remove duplicates
	# convert to cpe
	product_cpes = {}
	for p in products:
		cpes = process_input(p)
		for cpe in cpes:
			product_cpes[cpe['cpe23Uri']]=cpe
	if len(product_cpes) == 0:
		print("No CPEs to process. Quitting...")
		exit()
	##### process CPEs and write CVEs to file
	filename = args.outfile
	search_exploits = not args.noexploits
	generate_charts = not args.nocharts
	get_cwe_name()
	workbook = xlsxwriter.Workbook(filename)
	bold = workbook.add_format({'bold': True})

	link_count = 0

	number_format = workbook.add_format({'num_format': '0.0'})
	date_format = workbook.add_format({'num_format': 'YYYY-MM-DD'})
	wrap_format = workbook.add_format()
	wrap_format.set_text_wrap()
	product_cpe_uris_sorted=sorted(product_cpes)
	for cpe_uri in product_cpe_uris_sorted:
		cpe = product_cpes[cpe_uri]
		if cpe == None:
			continue
		link_count += 1
		title = cpe['titles'][0]['title']
		print("Processing: " + title)
		try:
			worksheet_title = get_worksheet_titel(str(link_count) + "_" , cpe_uri)
			worksheet = workbook.add_worksheet(worksheet_title)
			cves = get_cves_list(cpe_uri)
			row=0
			worksheet.merge_range(f'A{row+1}:D{row+1}',title, bold)
			row +=1
			worksheet.merge_range(f'A{row+1}:D{row+1}',unquote(cpe_uri))
			row +=1
			worksheet.merge_range(f'A{row+1}:D{row+1}',"")
			worksheet.write_url(row, 0,
								"https://www.google.com/search?q=" + quote_plus(
									get_product(cpe_uri) + " latest release"),
								string="Search for latest Version (Google)")
			row += 5
			table_first_row = row
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

				if search_exploits and str(CPE(unquote(cpe_uri)).get_product()[0]) != "":
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
			last_table_row = len(cves) + table_first_row
			all_cells = "A%d:" % (table_first_row) + chr(65 + col) + str(last_table_row)
			inner_cells = "A%d:" % (table_first_row + 1) + chr(65 + col) + str(last_table_row)
			worksheet.add_table(all_cells, {'columns': [{'header': 'CVE-ID'},
													{'header': 'Vulnerability Type'},
													{'header': 'Publish Date'},
													{'header': 'Score (2.0)'},
													{'header': 'Access'},
													{'header': 'Complexity'},
													{'header': 'Score (3.1)'},
													{'header': 'Vector (3.1)'},
													{'header': 'ExploitDB IDs'},
													{'header': 'Description'},
													]})

			# Light red fill with dark red text if CVE is disputed
			disputed_format = workbook.add_format({'italic':1})
			worksheet.conditional_format(inner_cells, {'type': 'formula',
													   'criteria': '=ISNUMBER(SEARCH("** DISPUTED **",$J%d))'%(table_first_row + 1),
													   'format': disputed_format})
			# Bold type for CVEs with available exploits
			exploit_format = workbook.add_format({'bold':1})
			worksheet.conditional_format(inner_cells, {'type': 'formula',
													   'criteria': '=ISNUMBER(SEARCH("+++Exploit References availible!+++",$J%d))'%(table_first_row + 1),
													   'format': exploit_format})
			worksheet.conditional_format(inner_cells, {'type': 'formula',
												 'criteria': '=NOT(ISBLANK($I%d))'%(table_first_row + 1),
												 'format': exploit_format})

			# Use conditional formatting to color rows according to severity
			worksheet.write(f'A{table_first_row-2}', "Coloring")
			worksheet.data_validation(f'B{table_first_row-2}', {'validate': 'list',
											  'source': [Coloring.coloring_off, Coloring.coloring_cvssv2, Coloring.coloring_cvssv3]})
			worksheet.write(f'B{table_first_row-2}', str(args.coloring))
			coloring_drop_down_cell = f'$B${table_first_row-2}'

			# Critical
			critical_format = workbook.add_format({'bg_color': '#000000',
												   'font_color': '#FFFFFF'})
			worksheet.conditional_format(inner_cells, {'type': 'formula',
													   'criteria': '=AND($G%d>=9,$G%d<=10,%s="%s")'%(table_first_row + 1, table_first_row + 1, coloring_drop_down_cell, Coloring.coloring_cvssv3),
													   'format': critical_format})
			# High
			high_format = workbook.add_format({'bg_color': '#d9534f'})
			worksheet.conditional_format(inner_cells, {'type': 'formula',
													   'criteria': '=AND($D%d>=7,$D%d<=10,%s="%s")'%(table_first_row + 1, table_first_row + 1, coloring_drop_down_cell, Coloring.coloring_cvssv2),
													   'format': high_format})
			worksheet.conditional_format(inner_cells, {'type': 'formula',
													   'criteria': '=AND($G%d>=7,$G%d<9,%s="%s")'%(table_first_row + 1, table_first_row + 1, coloring_drop_down_cell, Coloring.coloring_cvssv3),
													   'format': high_format})
			# Medium
			medium_format = workbook.add_format({'bg_color': '#ec971f'})
			worksheet.conditional_format(inner_cells, {'type': 'formula',
													   'criteria': '=AND($D%d>=4,$D%d<7,%s="%s")'%(table_first_row + 1, table_first_row + 1, coloring_drop_down_cell, Coloring.coloring_cvssv2),
													   'format': medium_format})
			worksheet.conditional_format(inner_cells, {'type': 'formula',
													   'criteria': '=AND($G%d>=4,$G%d<7,%s="%s")'%(table_first_row + 1, table_first_row + 1, coloring_drop_down_cell, Coloring.coloring_cvssv3),
													   'format': medium_format})
			# Low
			low_format = workbook.add_format({'bg_color': '#f2cc0c'})
			worksheet.conditional_format(inner_cells, {'type': 'formula',
													   'criteria': '=AND($D%d>=0,$D%d<4,%s="%s")'%(table_first_row + 1, table_first_row + 1, coloring_drop_down_cell, Coloring.coloring_cvssv2),
													   'format': low_format})
			worksheet.conditional_format(inner_cells, {'type': 'formula',
													   'criteria': '=AND($G%d>0,$G%d<4,%s="%s")'%(table_first_row + 1, table_first_row + 1, coloring_drop_down_cell, Coloring.coloring_cvssv3),
													   'format': low_format})
			column_width = [15, 18, 13, 10, 15, 12, 10, 39, 13, 250]
			for i in range(0, len(column_width)):
				worksheet.set_column(i, i, column_width[i])

			# Add Charts
			if generate_charts:
				cvss2_score_column = 3
				cvss3_score_column = 6
				category_column = cvss2_score_column-1
				gap_from_table = 3
				count_format = workbook.add_format({'num_format': '#""'})
				row += gap_from_table # add some space
				worksheet.write(row, category_column, "Critical")
				worksheet.write_formula(row, cvss3_score_column,'=SUMPRODUCT(SUBTOTAL(3,OFFSET(Table1[Score (3.1)],ROW(Table1[Score (3.1)])-MIN(ROW(Table1[Score (3.1)])),,1))*(Table1[Score (3.1)]>=9))-SUMPRODUCT(SUBTOTAL(3,OFFSET(Table1[Score (3.1)],ROW(Table1[Score (3.1)])-MIN(ROW(Table1[Score (3.1)])),,1))*(Table1[Score (3.1)]>10))', count_format)  # CVSSv3
				row += 1
				worksheet.write(row, category_column, "High")
				worksheet.write_formula(row, cvss2_score_column,'=SUMPRODUCT(SUBTOTAL(3,OFFSET(Table1[Score (2.0)],ROW(Table1[Score (2.0)])-MIN(ROW(Table1[Score (2.0)])),,1))*(Table1[Score (2.0)]>=7))-SUMPRODUCT(SUBTOTAL(3,OFFSET(Table1[Score (2.0)],ROW(Table1[Score (2.0)])-MIN(ROW(Table1[Score (2.0)])),,1))*(Table1[Score (2.0)]>10))', count_format)  # CVSSv2
				worksheet.write_formula(row, cvss3_score_column,f'=SUMPRODUCT(SUBTOTAL(3,OFFSET(Table1[Score (3.1)],ROW(Table1[Score (3.1)])-MIN(ROW(Table1[Score (3.1)])),,1))*(Table1[Score (3.1)]>=7))-SUMPRODUCT(SUBTOTAL(3,OFFSET(Table1[Score (3.1)],ROW(Table1[Score (3.1)])-MIN(ROW(Table1[Score (3.1)])),,1))*(Table1[Score (3.1)]>=9))', count_format)  # CVSSv3
				row += 1
				worksheet.write(row, category_column, "Medium")
				worksheet.write_formula(row, cvss2_score_column,f'=SUMPRODUCT(SUBTOTAL(3,OFFSET(Table1[Score (2.0)],ROW(Table1[Score (2.0)])-MIN(ROW(Table1[Score (2.0)])),,1))*(Table1[Score (2.0)]>=4))-SUMPRODUCT(SUBTOTAL(3,OFFSET(Table1[Score (2.0)],ROW(Table1[Score (2.0)])-MIN(ROW(Table1[Score (2.0)])),,1))*(Table1[Score (2.0)]>=7))', count_format)  # CVSSv2
				worksheet.write_formula(row, cvss3_score_column,f'=SUMPRODUCT(SUBTOTAL(3,OFFSET(Table1[Score (3.1)],ROW(Table1[Score (3.1)])-MIN(ROW(Table1[Score (3.1)])),,1))*(Table1[Score (3.1)]>=4))-SUMPRODUCT(SUBTOTAL(3,OFFSET(Table1[Score (3.1)],ROW(Table1[Score (3.1)])-MIN(ROW(Table1[Score (3.1)])),,1))*(Table1[Score (3.1)]>=7))', count_format)  # CVSSv3
				row += 1
				worksheet.write(row, category_column, "Low")
				worksheet.write_formula(row, cvss2_score_column,f'=SUMPRODUCT(SUBTOTAL(3,OFFSET(Table1[Score (2.0)],ROW(Table1[Score (2.0)])-MIN(ROW(Table1[Score (2.0)])),,1))*(Table1[Score (2.0)]>=0))-SUMPRODUCT(SUBTOTAL(3,OFFSET(Table1[Score (2.0)],ROW(Table1[Score (2.0)])-MIN(ROW(Table1[Score (2.0)])),,1))*(Table1[Score (2.0)]>=4))', count_format) # CVSSv2
				worksheet.write_formula(row, cvss3_score_column,f'=SUMPRODUCT(SUBTOTAL(3,OFFSET(Table1[Score (3.1)],ROW(Table1[Score (3.1)])-MIN(ROW(Table1[Score (3.1)])),,1))*(Table1[Score (3.1)]>0))-SUMPRODUCT(SUBTOTAL(3,OFFSET(Table1[Score (3.1)],ROW(Table1[Score (3.1)])-MIN(ROW(Table1[Score (3.1)])),,1))*(Table1[Score (3.1)]>=4))', count_format)  # CVSSv3
				row += 1
				worksheet.write(row, category_column, "None")
				worksheet.write_formula(row, cvss3_score_column,f'=SUMPRODUCT(SUBTOTAL(3,OFFSET(Table1[Score (3.1)],ROW(Table1[Score (3.1)])-MIN(ROW(Table1[Score (3.1)])),,1))*(Table1[Score (3.1)]=0))', count_format)  # CVSSv3
				row += 1
				worksheet.write(row, category_column, "N/A")
				worksheet.write_formula(row, cvss2_score_column,f'=SUBTOTAL(3,Table1[CVE-ID])-SUM({chr(65+cvss2_score_column)}{row-3}:{chr(65+cvss2_score_column)}{row})', count_format) # CVSSv2
				worksheet.write_formula(row, cvss3_score_column,f'=SUBTOTAL(3,Table1[CVE-ID])-SUM({chr(65+cvss3_score_column)}{row-4}:{chr(65+cvss3_score_column)}{row})', count_format)  # CVSSv3
				row += 1
				chart1 = workbook.add_chart({'type': 'doughnut'})
				chart1.add_series({
					'name':       'CVSSv2',
					'categories': [worksheet_title, last_table_row+gap_from_table, category_column, last_table_row+gap_from_table+5, category_column],
					'values':     [worksheet_title, last_table_row+gap_from_table, cvss2_score_column, last_table_row+gap_from_table+5, cvss2_score_column],
					'points': [
						{'fill': {'color': '#FFFFFF'}},
						{'fill': {'color': '#d9534f'}},
						{'fill': {'color': '#ec971f'}},
						{'fill': {'color': '#f2cc0c'}},
						{'fill': {'color': '#FFFFFF'}},
						{'fill': {'color': '#e0e0e0'}},
					],
					'data_labels': {'value': True, 'font': {'color': 'white', 'bold':1}, 'legend_key': True},
				})
				chart1.set_title({'name': 'CVSSv2'})
				chart1.set_legend({'position': 'bottom'})
				worksheet.insert_chart(f'{chr(65+category_column-1)}{last_table_row+gap_from_table-1}', chart1)

				chart2 = workbook.add_chart({'type': 'doughnut'})
				chart2.add_series({
					'name':       'CVSSv3',
					'categories': [worksheet_title, last_table_row+gap_from_table, category_column, last_table_row+gap_from_table+5, category_column],
					'values':     [worksheet_title, last_table_row+gap_from_table, cvss3_score_column, last_table_row+gap_from_table+5, cvss3_score_column],
					'points': [
						{'fill': {'color': '#000000'}},
						{'fill': {'color': '#d9534f'}},
						{'fill': {'color': '#ec971f'}},
						{'fill': {'color': '#f2cc0c'}},
						{'fill': {'color': '#bcdfeb'}},
						{'fill': {'color': '#e0e0e0'}},
					],
					'data_labels': {'value': True, 'font': {'color': 'white', 'bold':1}, 'legend_key': True},
				})
				chart2.set_title({'name': 'CVSSv3'})
				chart2.set_legend({'position': 'bottom'})
				worksheet.insert_chart(f'{chr(65+cvss3_score_column)}{last_table_row+gap_from_table-1}', chart2)
		except IndexError:
			print("ERROR")

	print("Your XLXS file has been successfully generated: %s" % filename)
	workbook.close()
