# VulnCollector

## Usage
```
VulnCollector.py [-h] [-o [outfile]] [-l [LIST ...]]
                        [-p [PRODUCTS ...]] [-n] [-c]
```

### Option 1
1. Go to https://nvd.nist.gov/vuln/search -> Advanced
2. Search for the software
3. Either copy the cpe String or click 'Search' and copy the link
4. Copy the cpe/link to a file (cvelist) or use it as input (cpes)

### Option 2
- Enter keywords to find the product. You will be prompted to select one, if your search matches several products.

**Output: CVE Table for related vulnerabilities (`outfile [default:cves.xlsx]`)**

### Optional Arguments:
- `-h`, `--help`            show this help message and exit
- `-o [outfile]`, `--outfile [outfile]` File where CVE Tables are written to
- `-l [LIST ...]`, `--list [LIST ...]` File with cpe/seach links/keyword or an NMAP XML scan result file
- `-p [PRODUCTS ...]`, `--products [PRODUCTS ...]` cpe/seach links/keyword
- `-n`, `--noexploits`      Don't lookup exploits
- `-c`, `--coloring`      Use conditional formatting to highlight rows according to severity (CVSSv3)

### Example Usage
```
VulnCollector.py -p cpe:/:apache:http_server:2.4.43
    Downloading and processing CWE List
    Processing: cpe:/:apache:http_server:2.4.43
    100%|██████████| 21/21 [00:18<00:00,  1.16it/s]
    Your XLXS file has been successfully generated: cves.xlsx
```

```
VulnCollector.py -p cpe:/:apache:http_server:2.4.43 -l list.txt nmap.xml
```

```
VulnCollector.py -p "jQuery 2.2.4"
    Select CPE for jQuery 2.2.4:
    [0] cpe:2.3:a:jquery:jquery:2.2.4:*:*:*:*:*:*:* 	 jQuery 2.2.4
    [1] cpe:2.3:a:no-margin-for-error:prettyphoto:2.2.4:*:*:*:*:wordpress:*:* 	 NO-MARGIN-FOR-ERROR prettyPhoto 2.2.4 for WordPress
    [2] cpe:2.3:a:jquery:jquery:2.2.4:*:*:*:*:node.js:*:* 	 jquery 2.2.4 for Node.js
    [A] All
    [N] None
    Select CPE: 0               # will select the first CPE
        or
    Select CPE: 0 2             # will select the first and last CPE
```

### Notification
- `Could not find any CPEs for ...` No matching CPE was found. Try another keyword. However, keep in mind that CPEs are only found if there are any CVEs related to them.

## Output

|CVE-ID|Vulnerability Type|Publish Date|Score (2.0)|Access|Complexity|Score (3.1)|Vector (3.1)|ExploitDB IDs|Description|
|---|---|---|---|---|---|---|---|---|---|
||||||||||