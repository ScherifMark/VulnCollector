# VulnCollector

## Usage
```
VulnCollector.py [-h] [--outfile [outfile]] [--cpelist [CPELIST ...]]
[--cpes [CPES ...]] [--noexploits]
```

1. Go to https://nvd.nist.gov/vuln/search -> Advanced
2. Search for the software
3. Either copy the cpe String or click 'Search' and copy the link
4. Copy the cpe/link to a file (cvelist) or use it as input (cpes)

**Output: CVE Table for related vulnerabilities (`outfile [default:cves.xlsx]`)**

### Optional Arguments:
- `-h`, `--help`            show this help message and exit
- `--outfile [outfile]`   File where CVE Tables are written to
- `--cpelist [CPELIST ...]` File with cpe/links
- `--cpes [CPES ...]`     cpe/link
- `--noexploits`          Don't lookup exploits

### Example Usage
```
VulnCollector.py --cpes cpe:/:apache:http_server:2.4.43
    Downloading and processing CWE List
    Processing: cpe:/:apache:http_server:2.4.43
    100%|██████████| 21/21 [00:18<00:00,  1.16it/s]
    Your XLXS file has been successfully generated: cves.xlsx
```


## Output

|CVE-ID|Vulnerability Type|Publish Date|Score (2.0)|Access|Complexity|Score (3.1)|Vector (3.1)|ExploitDB IDs|Description|
|---|---|---|---|---|---|---|---|---|---|
||||||||||