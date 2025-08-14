# AI-Feed-Reader
This project is for tracking emerging threats and leveraging local LLMs to summarize and extract IOCs
# AI-EmergingThreats

Threat intelligence newsletter generator that:
- Fetches cybersecurity blogs/RSS feeds
- Summarizes each item with a local LLM (Qwen via Ollama)
- Extracts IoCs (IPs, domains, file hashes) and MITRE techniques (T-IDs)
- Deduplicates similar stories and merges sources
- Produces a categorized report and CSVs in a per-run folder

## Key features
- Robust RSS loader: accepts plain URLs, key:"url" lines, or JSON dict/list (rss_feeds.txt)
- SSL verification is ignored by default to avoid fetch failures (configurable)
- Per-run output folder: news-letter-YYYYMMDD_HHMMSS with all artifacts
- Persistent state (feed_state.json): skips links already processed
- Recency window: only process posts within last 24 hours (configurable in code)
- De-duplication with CVE grouping and title fingerprinting, optional LLM merge
- Techniques extraction: detects MITRE T-IDs (e.g., T1059, T1027.003)

## Outputs
In news-letter-<timestamp>/ you will find:
- threat_intel_analysis.csv (stable) and threat_intel_analysis_<timestamp>.csv
  - Columns: url, title, link, summary, relevant_for_threat_intel, iocs_present,
    threat_actors_mentioned, published, ips, domains, hashes, techniques
- ip4_<timestamp>.csv, domains_<timestamp>.csv, filehashes_<timestamp>.csv, mitre_ttps_<timestamp>.csv
- threat_intel_report.txt (categorized, deduplicated report)

## Prerequisites
- macOS with Python 3.10+ recommended
- Optional: Ollama running locally for Qwen (improves summaries/merging)
  - Install: https://ollama.com
  - Start: ollama serve
  - Pull model: ollama pull qwen2.5:7b

## Install (venv recommended)
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install aiohttp feedparser beautifulsoup4 tldextract requests certifi openai lxml
```

## Usage
From the AI-EmergingThreats directory:
- Default (no flags): analyze feeds and generate report with defaults
  ```bash
  python3 feedreader.py
  ```
- Analyze only:
  ```bash
  python3 feedreader.py --analyze
  ```
- Generate report only (uses latest CSV by default name if present):
  ```bash
  python3 feedreader.py --generate-report
  ```
- Help:
  ```bash
  python3 feedreader.py -h
  ```

## rss_feeds.txt format
- Plain URL per line:
  ```
  https://www.darkreading.com/rss.xml
  ```
- Key:"url" line:
  ```
  "BlogZeroFox": "https://www.zerofox.com/blog/feed",
  ```
- JSON dict or list:
  ```json
  {"zdi": "https://www.zerodayinitiative.com/rss/published/", "hn": "https://feeds.feedburner.com/TheHackersNews"}
  ```

The loader extracts only valid http(s) URLs and de-duplicates.

## LLM usage (Qwen via Ollama)
- Used to summarize entries and to merge duplicate stories into one block while merging sources.
- If Ollama is not running, the app falls back to keyword summaries/heuristics.

## Recency & state
- feed_state.json stores processed links and timestamps to avoid re-processing.
- By default, only items within the last 24 hours are processed.
- To reprocess everything, delete feed_state.json (not recommended for large runs).

## SSL verification
- SSL verification is skipped by default to keep feeds working even with misconfigured chains.
- Toggle via environment variable:
  ```bash
  export SKIP_SSL_VERIFY=true   # default
  export SKIP_SSL_VERIFY=false  # enable verification
  ```

## Folder structure per run
```
news-letter-YYYYMMDD_HHMMSS/
  threat_intel_analysis.csv
  threat_intel_analysis_YYYYMMDD_HHMMSS.csv
  threat_intel_report.txt
  ip4_YYYYMMDD_HHMMSS.csv
  domains_YYYYMMDD_HHMMSS.csv
  filehashes_YYYYMMDD_HHMMSS.csv
  mitre_ttps_YYYYMMDD_HHMMSS.csv
```

## Troubleshooting
- No output / exits quickly
  - Ensure rss_feeds.txt exists with at least one valid URL
  - Run with: python3 feedreader.py --analyze
- LLM merge/summarize not working
  - Start Ollama: ollama serve
  - Pull model: ollama pull qwen2.5:7b
- SSL errors
  - Default skips verification; ensure SKIP_SSL_VERIFY=true
- Re-run all content
  - Remove feed_state.json to reset processed link memory
- Domain overmatching
  - tldextract normalizes domains; filenames like 1.js are ignored by pattern + tldextract

## License
Internal/unspecified. Add a license if distributing.

## Disclaimer
Disabling SSL verification reduces transport security. Use only in trusted environments.
