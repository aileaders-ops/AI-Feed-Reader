#!/usr/bin/env python3
"""
Threat Intelligence RSS Feed Analyzer
Monitors 400+ RSS feeds for threat intel, extracts IoCs, and summarizes content using Ollama
"""

import asyncio
import aiohttp
import feedparser
import csv
import re
import json
import logging
import ssl
import certifi
import os
from datetime import datetime, timedelta
import calendar
from pathlib import Path
from typing import List, Dict, Set, Tuple, Any, Optional
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET
from openai import OpenAI
import requests
import tldextract
import argparse
from collections import defaultdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('threat_intel_analyzer.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize the local LLM client (Ollama via OpenAI-compatible API)
client = OpenAI(
    base_url='http://localhost:11434/v1/',  # Local LLM server URL
    api_key='ollama',                       # Required but ignored for local LLM
)

# Global toggle: ignore SSL verification by default (user can override via env)
SKIP_SSL_VERIFY = os.getenv("SKIP_SSL_VERIFY", "true").lower() in ("1", "true", "yes")

def fetch_url_content(url: str):
    """Fetch the content of a URL."""
    try:
        # Ignore SSL verification by default
        verify_opt = False if SKIP_SSL_VERIFY else certifi.where()
        response = requests.get(url, timeout=20, verify=verify_opt)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        return soup.get_text(separator=' ', strip=True)
    except Exception as e:
        logger.error(f"Error fetching URL content: {e}")
        return None

def query_local_llm(prompt: str) -> str:
    """Query the local LLM with a given prompt."""
    try:
        chat_completion = client.chat.completions.create(
            messages=[{'role': 'user', 'content': prompt}],
            model='qwen2.5:7b',  # Specify the local model
        )
        if chat_completion.choices and len(chat_completion.choices) > 0:
            return chat_completion.choices[0].message.content.strip()
        return "No response received."
    except Exception as e:
        logger.error(f"Error querying the local LLM: {e}")
        return "Error processing your request."

class ThreatIntelAnalyzer:
    def __init__(self, ollama_host="http://localhost:11434/v1/", model="qwen2.5:7b",
                 allow_insecure_fallback=True, skip_ssl_verify: bool = SKIP_SSL_VERIFY):
        self.ollama_host = ollama_host
        self.model = model
        self.session = None
        self.allow_insecure_fallback = allow_insecure_fallback
        # If skip_ssl_verify=True, disable SSL verification for aiohttp
        self.skip_ssl_verify = skip_ssl_verify
        self.ssl_context = False if self.skip_ssl_verify else ssl.create_default_context(cafile=certifi.where())
        
        # IoC patterns
        self.ip_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )
        self.domain_pattern = re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        )
        self.hash_patterns = {
            'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
            'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
            'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
            'sha512': re.compile(r'\b[a-fA-F0-9]{128}\b')
        }
        
        # MITRE TTP pattern
        self.mitre_ttp_pattern = re.compile(r'\bT-?\d{4}(?:\.\d{3})?\b')

        
        # Threat actor keywords
        self.threat_actors = [
            'apt1', 'apt28', 'apt29', 'apt34', 'apt40', 'lazarus', 'carbanak',
            'fancy bear', 'cozy bear', 'equation group', 'shadow brokers',
            'ransomware', 'conti', 'ryuk', 'maze', 'lockbit', 'revil',
            'emotet', 'trickbot', 'qakbot', 'dridex', 'ursnif',
            'mirai', 'gh0st', 'cobalt strike', 'metasploit'
        ]
        
        # Results storage
        self.results = []
        self.ips = set()
        self.domains = set()
        self.hashes = set()
        self.techniques = set()
        # Persistence and recency controls
        self.state_path = Path("feed_state.json")
        self.only_recent_hours = 24  # default 24h window
        self.only_recent = True      # process only posts within window
        self.state = {"version": 1, "entries": {}}  # link -> iso timestamp
        self._load_state()
        # Defer lock creation to __aenter__
        self.state_lock = None
        # newsletter run output directory (set on save)
        self.run_dir: Path | None = None
    
    async def __aenter__(self):
        # If self.ssl_context is False, aiohttp disables verification
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            connector=aiohttp.TCPConnector(limit=50, ssl=self.ssl_context)
        )
        # Create lock in event loop
        self.state_lock = asyncio.Lock()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    def parse_html_content(self, html_content: str) -> str:
        """Parse HTML content and extract text"""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            # Remove script and style elements
            for script in soup(["script", "style"]):
                script.extract()
            text = soup.get_text()
            # Clean up whitespace
            lines = (line.strip() for line in text.splitlines())
            chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
            return ' '.join(chunk for chunk in chunks if chunk)
        except Exception as e:
            logger.error(f"Error parsing HTML: {e}")
            return html_content
    
    def _load_state(self):
        try:
            if self.state_path.exists():
                with open(self.state_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict) and "entries" in data:
                        self.state = data
        except Exception as e:
            logger.warning(f"Could not load state file {self.state_path}: {e}")

    def _save_state(self):
        try:
            tmp = self.state_path.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.state, f, indent=2)
            tmp.replace(self.state_path)
        except Exception as e:
            logger.warning(f"Could not save state file {self.state_path}: {e}")

    def _parse_entry_published(self, entry) -> datetime | None:
        # Prefer feedparser's structured time when available
        if hasattr(entry, "published_parsed") and entry.published_parsed:
            try:
                ts = calendar.timegm(entry.published_parsed)
                return datetime.utcfromtimestamp(ts).replace(tzinfo=None)
            except Exception:
                pass
        # Fallback: try string; many feeds already include human string; leave None if unknown
        return None

    def _should_process(self, link: str, published_dt: datetime | None) -> bool:
        # Skip if already seen
        if link in self.state["entries"]:
            return False
        # If only recent window is enabled, enforce it when we have a timestamp
        if self.only_recent and published_dt:
            cutoff = datetime.utcnow() - timedelta(hours=self.only_recent_hours)
            if published_dt < cutoff:
                return False
        return True

    async def _mark_processed(self, link: str, published_dt: datetime | None):
        iso = (published_dt or datetime.utcnow()).strftime("%Y-%m-%dT%H:%M:%SZ")
        async with self.state_lock:
            self.state["entries"][link] = iso

    async def fetch_rss_feed(self, url: str) -> List[Dict]:
        """Fetch and parse RSS feed"""
        try:
            # Use connector SSL config (verification disabled by default)
            async with self.session.get(url) as response:
                if response.status != 200:
                    logger.warning(f"Failed to fetch {url}: HTTP {response.status}")
                    return []
                content = await response.text()
        except Exception as e:
            logger.error(f"Error fetching RSS feed {url}: {e}")
            return []

        # Parse feed content
        feed = feedparser.parse(content)
        if feed.bozo:
            logger.warning(f"Malformed feed: {url}")

        entries = []
        for entry in feed.entries[:10]:
            raw = ""
            if hasattr(entry, 'content'):
                raw = entry.content[0].value
            elif hasattr(entry, 'description'):
                raw = entry.description
            elif hasattr(entry, 'summary'):
                raw = entry.summary

            published_dt = self._parse_entry_published(entry)
            text_content = self.parse_html_content(raw)
            entries.append({
                'title': getattr(entry, 'title', 'No title'),
                'link': getattr(entry, 'link', ''),
                'content': text_content,
                'published': getattr(entry, 'published', ''),
                'published_iso': published_dt.strftime("%Y-%m-%dT%H:%M:%SZ") if published_dt else ''
            })
        return entries
    
    async def summarize_with_ollama(self, content: str) -> Dict:
        """Summarize content using local Ollama (OpenAI-compatible client)."""
        prompt = f"""
Analyze the following cybersecurity/threat intelligence content and provide:
1) A 50-word summary
2) Whether it's relevant for threat intelligence tracking (yes/no)
3) Any threat actors mentioned (comma-separated list or "none")

Content:
{content[:2000]}

Respond ONLY in JSON:
{{
  "summary": "50-word summary here",
  "relevant": "yes/no",
  "threat_actors": "actor1, actor2 or none"
}}
"""
        try:
            # Run sync client call in a thread to avoid blocking the event loop
            response_text = await asyncio.to_thread(query_local_llm, prompt)

            # Try to parse JSON from the model output
            try:
                json_start = response_text.find('{')
                json_end = response_text.rfind('}') + 1
                if json_start >= 0 and json_end > json_start:
                    json_str = response_text[json_start:json_end]
                    analysis = json.loads(json_str)
                    # Minimal normalization
                    return {
                        "summary": analysis.get("summary", "")[:600],
                        "relevant": analysis.get("relevant", "no").lower(),
                        "threat_actors": analysis.get("threat_actors", "none")
                    }
            except json.JSONDecodeError:
                logger.warning("Failed to parse JSON from local LLM response")

            return self._fallback_analysis(content)
        except Exception as e:
            logger.error(f"Ollama/OpenAI client error: {e}")
            return self._fallback_analysis(content)
    
    def _fallback_analysis(self, content: str) -> Dict:
        """Fallback analysis without Ollama"""
        # Simple keyword-based analysis
        content_lower = content.lower()
        
        # Check relevance
        threat_keywords = [
            'malware', 'ransomware', 'apt', 'vulnerability', 'exploit',
            'phishing', 'botnet', 'trojan', 'backdoor', 'zero-day',
            'ioc', 'indicator', 'compromise', 'breach', 'attack',
            'threat', 'cybersecurity', 'security'
        ]
        
        relevant = any(keyword in content_lower for keyword in threat_keywords)
        
        # Find threat actors
        mentioned_actors = []
        for actor in self.threat_actors:
            if actor in content_lower:
                mentioned_actors.append(actor)
        
        # Generate simple summary (first 50 words)
        words = content.split()[:50]
        summary = ' '.join(words)
        
        return {
            "summary": summary,
            "relevant": "yes" if relevant else "no",
            "threat_actors": ', '.join(mentioned_actors) if mentioned_actors else "none"
        }
    
    def extract_iocs_and_ttps(self, content: str) -> Tuple[Set[str], Set[str], Set[str], Set[str]]:
        """Extract IoCs and MITRE TTPs from content"""
        ips, domains, hashes, techniques = set(), set(), set(), set()
        
        # Extract IPs
        ip_matches = self.ip_pattern.findall(content)
        for ip in ip_matches:
            if not (ip.startswith('127.') or ip.startswith('192.168.') or 
                   ip.startswith('10.') or ip.startswith('0.') or
                   ip.endswith('.0') or ip.endswith('.255')):
                ips.add(ip)
        
        # Extract domains
        domain_matches = self.domain_pattern.findall(content)
        for domain in domain_matches:
            extracted = tldextract.extract(domain)
            if extracted.domain and extracted.suffix:
                normalized_domain = f"{extracted.domain}.{extracted.suffix}"
                domains.add(normalized_domain.lower())
        
        # Extract hashes
        for hash_type, pattern in self.hash_patterns.items():
            hash_matches = pattern.findall(content)
            for hash_val in hash_matches:
                hashes.add(hash_val.lower())
        
        # Extract MITRE TTPs
        ttp_matches = self.mitre_ttp_pattern.findall(content)
        techniques.update(ttp_matches)
        
        return ips, domains, hashes, techniques
    
    async def analyze_feed(self, rss_url: str) -> None:
        """Analyze a single RSS feed"""
        logger.info(f"Analyzing feed: {rss_url}")
        try:
            entries = await self.fetch_rss_feed(rss_url)
            for entry in entries:
                link = entry.get('link', '')
                # Parse iso if present
                published_iso = entry.get('published_iso') or ''
                published_dt = None
                if published_iso:
                    try:
                        # naive UTC assumed since we stored Z
                        published_dt = datetime.strptime(published_iso, "%Y-%m-%dT%H:%M:%SZ")
                    except Exception:
                        published_dt = None

                if not self._should_process(link, published_dt):
                    continue

                # Combine title and content for analysis
                full_content = f"{entry['title']} {entry['content']}"
                analysis = await self.summarize_with_ollama(full_content)

                # Extract IoCs and TTPs
                ips, domains, hashes, techniques = self.extract_iocs_and_ttps(full_content)

                # Store results
                self.results.append({
                    'url': rss_url,
                    'title': entry['title'],
                    'link': link,
                    'summary': analysis['summary'],
                    'relevant_for_threat_intel': analysis['relevant'],
                    'iocs_present': 'True' if (ips or domains or hashes) else 'False',
                    'threat_actors_mentioned': analysis['threat_actors'],
                    'published': entry['published'],
                    'ips': ', '.join(ips),
                    'domains': ', '.join(domains),
                    'hashes': ', '.join(hashes),
                    'techniques': ', '.join(techniques)
                })

                # Mark processed
                await self._mark_processed(link, published_dt)

        except Exception as e:
            logger.error(f"Error analyzing feed {rss_url}: {e}")
    
    def save_results_to_csv(self):
        """Save analysis results to CSV files. Also write a stable latest file in a run folder."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Create newsletter run directory
        self.run_dir = Path(f"news-letter-{timestamp}")
        self.run_dir.mkdir(parents=True, exist_ok=True)

        # Timestamped and stable filenames inside the run folder
        main_csv_ts = self.run_dir / f"threat_intel_analysis_{timestamp}.csv"
        main_csv_latest = self.run_dir / "threat_intel_analysis.csv"

        with open(main_csv_ts, 'w', newline='', encoding='utf-8') as f:
            fieldnames = [
                'url', 'title', 'link', 'summary', 'relevant_for_threat_intel',
                'iocs_present', 'threat_actors_mentioned', 'published',
                'ips', 'domains', 'hashes', 'techniques'
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.results)

        # Also write/update stable copy
        with open(main_csv_latest, 'w', newline='', encoding='utf-8') as f:
            fieldnames = [
                'url', 'title', 'link', 'summary', 'relevant_for_threat_intel',
                'iocs_present', 'threat_actors_mentioned', 'published',
                'ips', 'domains', 'hashes', 'techniques'
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.results)

        logger.info(f"Main results saved to {main_csv_ts} and {main_csv_latest}")

        # IP addresses
        if self.ips:
            ip_csv = self.run_dir / f"ip4_{timestamp}.csv"
            with open(ip_csv, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['ip_address', 'source'])
                for ip in sorted(self.ips):
                    writer.writerow([ip, "RSS Feeds"])
            logger.info(f"IP addresses saved to {ip_csv}")
        
        # Domains
        if self.domains:
            domain_csv = self.run_dir / f"domains_{timestamp}.csv"
            with open(domain_csv, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['domain', 'source'])
                for domain in sorted(self.domains):
                    writer.writerow([domain, "RSS Feeds"])
            logger.info(f"Domains saved to {domain_csv}")
        
        # File hashes
        if self.hashes:
            hash_csv = self.run_dir / f"filehashes_{timestamp}.csv"
            with open(hash_csv, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['hash', 'type', 'source'])
                for hash_val in sorted(self.hashes):
                    hash_type = 'unknown'
                    if len(hash_val) == 32:
                        hash_type = 'md5'
                    elif len(hash_val) == 40:
                        hash_type = 'sha1'
                    elif len(hash_val) == 64:
                        hash_type = 'sha256'
                    elif len(hash_val) == 128:
                        hash_type = 'sha512'
                    writer.writerow([hash_val, hash_type, "RSS Feeds"])
            logger.info(f"File hashes saved to {hash_csv}")
        
        # MITRE TTPs
        if self.techniques:
            ttp_csv = self.run_dir / f"mitre_ttps_{timestamp}.csv"
            with open(ttp_csv, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['technique', 'source'])
                for ttp in sorted(self.techniques):
                    writer.writerow([ttp, "RSS Feeds"])
            logger.info(f"MITRE TTPs saved to {ttp_csv}")

        # Return the stable file path for downstream steps
        return str(main_csv_latest)

    async def analyze_feeds(self, rss_urls: List[str]):
        """Analyze multiple RSS feeds concurrently"""
        logger.info(f"Starting analysis of {len(rss_urls)} RSS feeds")
        batch_size = 10
        for i in range(0, len(rss_urls), batch_size):
            batch = rss_urls[i:i+batch_size]
            tasks = [self.analyze_feed(url) for url in batch]
            await asyncio.gather(*tasks, return_exceptions=True)
            logger.info(f"Completed batch {i//batch_size + 1}/{(len(rss_urls)-1)//batch_size + 1}")
            await asyncio.sleep(2)

        # Save results and state
        saved_csv = self.save_results_to_csv()
        self._save_state()

        logger.info(f"Analysis complete!")
        logger.info(f"Total entries analyzed: {len(self.results)}")
        logger.info(f"IP addresses found: {len(self.ips)}")
        logger.info(f"Domains found: {len(self.domains)}")
        logger.info(f"File hashes found: {len(self.hashes)}")
        logger.info(f"MITRE TTPs found: {len(self.techniques)}")

        return saved_csv

def _is_valid_url(u: str) -> bool:
    try:
        p = urlparse(u.strip())
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False

def load_rss_feeds(file_path: str) -> List[str]:
    """Load only RSS feed URLs from rss_feeds.txt.

    Supports:
    - Plain URLs per line
    - key: "url", lines (e.g., "BlogZeroFox": "https://.../feed",)
    - JSON dict/list with URLs or objects containing url/feed/href
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        urls: List[str] = []

        # 1) Try full-file JSON first (dict or list)
        try:
            data = json.loads(content)
            if isinstance(data, dict):
                for v in data.values():
                    if isinstance(v, str) and _is_valid_url(v):
                        urls.append(v.strip())
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, str) and _is_valid_url(item):
                        urls.append(item.strip())
                    elif isinstance(item, dict):
                        for k in ("url", "feed", "href"):
                            if k in item and isinstance(item[k], str) and _is_valid_url(item[k]):
                                urls.append(item[k].strip())
                                break
        except json.JSONDecodeError:
            # 2) Fallback: extract any URLs from the text (handles key:"value", trailing commas, etc.)
            for m in re.findall(r'https?://[^\s"\',)]+', content):
                if _is_valid_url(m):
                    urls.append(m.strip())

        # Deduplicate while preserving order
        seen = set()
        deduped: List[str] = []
        for u in urls:
            if u not in seen:
                seen.add(u)
                deduped.append(u)

        if not deduped:
            logger.error("No valid RSS URLs found in rss_feeds.txt")
        else:
            logger.info(f"Loaded {len(deduped)} RSS URLs")

        return deduped

    except FileNotFoundError:
        logger.error(f"RSS feeds file not found: {file_path}")
        return []

# --- Helpers for de-duplicating and merging similar stories in the report ---
def _extract_cves(text: str) -> Set[str]:
    """Return set of CVE IDs found in text."""
    cves = set(re.findall(r'\bCVE-\d{4}-\d{4,7}\b', text, flags=re.IGNORECASE))
    return {c.upper() for c in cves}

_STOPWORDS = {
    "the","and","for","with","from","this","that","into","over","when","your",
    "about","using","has","have","was","were","are","is","of","to","in","on",
    "by","a","an","as","via","new","how","why","what"
}

def _fingerprint_title(title: str) -> str:
    """Heuristic fingerprint for titles when no CVE is present."""
    t = re.sub(r'[^A-Za-z0-9\s-]', ' ', (title or "").lower())
    tokens = [w for w in t.split() if len(w) >= 4 and w not in _STOPWORDS]
    return ' '.join(sorted(tokens)[:8]) or t.strip()[:50]

def _merge_group_with_llm(items: List[Dict]) -> Tuple[str, str]:
    """
    Use local Qwen to produce a single consolidated title and summary
    for a group of similar items.
    """
    # Build a compact prompt
    lines = []
    for idx, it in enumerate(items, 1):
        lines.append(f"{idx}. Title: {it.get('title','')}\nSummary: {it.get('summary','')}")
    prompt = f"""You are consolidating duplicate cybersecurity news items.
Given multiple entries that describe the same event, produce:
- merged_title: a concise, specific title (max 120 chars)
- merged_summary: a clear 2-4 sentence summary (<= 600 chars total)

Entries:
{chr(10).join(lines)}

Respond ONLY in JSON:
{{
  "merged_title": "string",
  "merged_summary": "string"
}}"""

    try:
        resp = query_local_llm(prompt)
        # Parse JSON region
        start = resp.find("{")
        end = resp.rfind("}") + 1
        if start >= 0 and end > start:
            obj = json.loads(resp[start:end])
            merged_title = obj.get("merged_title") or items[0].get("title","")
            merged_summary = obj.get("merged_summary") or items[0].get("summary","")
            return merged_title.strip(), merged_summary.strip()
    except Exception as e:
        logger.warning(f"LLM merge failed, falling back: {e}")

    # Fallback: choose longest title/summary in group
    titles = sorted((it.get("title","") for it in items), key=len, reverse=True)
    summaries = sorted((it.get("summary","") for it in items), key=len, reverse=True)
    return (titles[0] if titles else "Untitled", summaries[0] if summaries else "")

def _dedupe_and_merge(items: List[Dict], use_llm: bool = True) -> List[Dict]:
    """
    Group similar items (by CVE or title fingerprint) and merge sources.
    Optionally use LLM to consolidate title/summary.
    """
    groups: Dict[str, List[Dict]] = {}

    for it in items:
        title = it.get("title","")
        summary = it.get("summary","")
        text = f"{title} {summary}"
        cves = sorted(_extract_cves(text))
        if cves:
            key = "CVE:" + ",".join(cves)
        else:
            key = "FP:" + _fingerprint_title(title)
        groups.setdefault(key, []).append(it)

    merged: List[Dict] = []
    for key, grp in groups.items():
        # Merge sources
        all_sources = []
        seen = set()
        for it in grp:
            for s in it.get("sources", []):
                if s and s not in seen:
                    seen.add(s)
                    all_sources.append(s)

        if len(grp) == 1:
            merged.append({
                "title": grp[0].get("title",""),
                "summary": grp[0].get("summary",""),
                "sources": all_sources or grp[0].get("sources", [])
            })
            continue

        if use_llm:
            title, summary = _merge_group_with_llm(grp)
        else:
            # Heuristic fallback
            titles = sorted((it.get("title","") for it in grp), key=len, reverse=True)
            summaries = sorted((it.get("summary","") for it in grp), key=len, reverse=True)
            title = titles[0] if titles else "Untitled"
            summary = summaries[0] if summaries else ""

        merged.append({"title": title, "summary": summary, "sources": all_sources})

    return merged

def generate_report(input_csv: str, output_file: str):
    """
    Reads the CSV file, filters rows where 'relevant_for_threat_intel' is 'yes',
    merges duplicate/similar items (keeping one description with all sources),
    and generates a categorized report.
    """
    # Categories for the report
    categories_items: Dict[str, List[Dict]] = {
        "Critical – Vulnerabilities": [],
        "Malware/Ransomware Threats": []
    }

    # Keywords to classify content
    vulnerability_keywords = ["vulnerability", "cve", "rce", "zero-day", "exploit", "critical", "patch", "remote code execution"]
    malware_keywords = ["malware", "ransomware", "apt", "stealer", "trojan", "backdoor", "botnet", "infostealer"]

    # Read the CSV file
    with open(input_csv, 'r', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            if row.get("relevant_for_threat_intel", "").lower() != "yes":
                continue

            title = (row.get("title") or "").strip()
            summary = (row.get("summary") or "").strip()
            source = (row.get("link") or "").strip()
            content = f"{title} {summary}".lower()

            entry = {"title": title, "summary": summary, "sources": [source] if source else []}

            if any(k in content for k in vulnerability_keywords):
                categories_items["Critical – Vulnerabilities"].append(entry)
            elif any(k in content for k in malware_keywords):
                categories_items["Malware/Ransomware Threats"].append(entry)
            else:
                # Default to vulnerabilities if unclassified
                categories_items["Critical – Vulnerabilities"].append(entry)

    # De-duplicate and merge per category (uses Qwen)
    merged_categories: Dict[str, List[Dict]] = {
        cat: _dedupe_and_merge(items, use_llm=True)
        for cat, items in categories_items.items()
    }

    # Write the report to the output file (same format, but Sources merged)
    with open(output_file, 'w', encoding='utf-8') as outfile:
        for category, entries in merged_categories.items():
            outfile.write(f"{category}\n\n")
            for it in entries:
                sources_line = "Source: " + ", ".join(it.get("sources", [])) if it.get("sources") else "Source: N/A"
                outfile.write(f"{it.get('title','No title')}\n{it.get('summary','No summary')}\n{sources_line}\n\n")
            outfile.write("\n")

    print(f"Report generated: {output_file}")

def _safe_parse_json_block(resp: str) -> Optional[dict]:
    try:
        start = resp.find("{")
        end = resp.rfind("}") + 1
        if start >= 0 and end > start:
            return json.loads(resp[start:end])
    except Exception:
        pass
    return None

def _write_text_report(structured: Dict[str, Any], out_path: Path) -> None:
    with open(out_path, 'w', encoding='utf-8') as f:
        for category in structured.get("categories", {}):
            f.write(f"{category}\n\n")
            for item in structured["categories"][category]:
                title = item.get("title", "No title")
                summary = item.get("summary", "No summary")
                sources = item.get("sources", [])
                src_line = "Source: " + ", ".join(sources) if sources else "Source: N/A"
                f.write(f"{title}\n{summary}\n{src_line}\n\n")
            f.write("\n")

def _write_html_report(structured: Dict[str, Any], out_path: Path) -> None:
    def esc(t: str) -> str:
        return (t or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
    html_parts = []
    html_parts.append("""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Threat Intelligence Report</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:20px;color:#111}
h1{font-size:24px;margin:0 0 12px}
h2{font-size:20px;margin:24px 0 12px;border-bottom:1px solid #ddd;padding-bottom:6px}
.article{margin:14px 0 18px}
.title{font-weight:600;margin-bottom:6px}
.summary{margin:4px 0 6px}
.sources a{color:#0645AD;text-decoration:none}
.sources a:hover{text-decoration:underline}
</style>
</head>
<body>
<h1>Threat Intelligence Report</h1>
""")
    for category in structured.get("categories", {}):
        html_parts.append(f"<h2>{esc(category)}</h2>")
        for item in structured["categories"][category]:
            title = esc(item.get("title", "No title"))
            summary = esc(item.get("summary", "No summary"))
            links = item.get("sources", [])
            links_html = ", ".join(f'<a href="{esc(u)}" target="_blank" rel="noopener noreferrer">{esc(u)}</a>' for u in links)
            html_parts.append(f'<div class="article"><div class="title">{title}</div>')
            html_parts.append(f'<div class="summary">{summary}</div>')
            html_parts.append(f'<div class="sources"><strong>Source:</strong> {links_html if links_html else "N/A"}</div></div>')
    html_parts.append("</body></html>")
    out_path.write_text("\n".join(html_parts), encoding="utf-8")

def _fallback_structured_from_text(report_text: str) -> Dict[str, Any]:
    # Minimal parser: split by category headers and group items by blank lines
    categories = ["Critical – Vulnerabilities", "Malware/Ransomware Threats"]
    current_cat = None
    structured: Dict[str, Any] = {"categories": {c: [] for c in categories}}
    buf: list[str] = []

    def flush_buf():
        nonlocal buf, current_cat
        if current_cat and buf:
            # Expect: title, summary, Source: ...
            title = buf[0].strip() if len(buf) > 0 else "Untitled"
            summary = buf[1].strip() if len(buf) > 1 else ""
            sources = []
            for line in buf:
                if line.strip().lower().startswith("source:"):
                    part = line.split(":", 1)[1].strip()
                    sources = [s.strip() for s in part.split(",") if s.strip()]
                    break
            structured["categories"][current_cat].append({"title": title, "summary": summary, "sources": sources})
            buf = []

    for line in report_text.splitlines():
        if line.strip() in categories:
            flush_buf()
            current_cat = line.strip()
            continue
        if not line.strip():
            flush_buf()
        else:
            buf.append(line)
    flush_buf()
    return structured

def postprocess_report_with_llm(text_report_path: Path) -> Tuple[Optional[Path], Optional[Path]]:
    """
    Send threat_intel_report.txt to the LLM to:
    1) Deduplicate items by title/summary, merging links into 'sources'.
    2) Produce an HTML report with clickable links.
    Returns (dedup_text_path, html_path).
    """
    raw = text_report_path.read_text(encoding="utf-8", errors="ignore")
    prompt = f"""You are given a threat intelligence report with two categories:
- "Critical – Vulnerabilities"
- "Malware/Ransomware Threats"

Each item is formatted as:
Title
Summary
Source: <link1>[, <link2>, ...]

Task:
1) Identify duplicates (same or highly similar title/summary). Keep one item and merge all links into a single sources list.
2) Return a single JSON object with structure exactly:
{{
  "categories": {{
    "Critical – Vulnerabilities": [{{"title": "...","summary": "...","sources": ["...", "..."]}} ],
    "Malware/Ransomware Threats": [{{"title": "...","summary": "...","sources": ["...", "..."]}} ]
  }}
}}

Here is the report to process:

{raw}
"""
    try:
        resp = query_local_llm(prompt)
        data = _safe_parse_json_block(resp)
        if not data or "categories" not in data:
            raise ValueError("LLM did not return expected JSON")
        # Write outputs next to source file
        dedup_txt = text_report_path.with_name("threat_intel_report_dedup.txt")
        html_out = text_report_path.with_name("threat_intel_report.html")
        _write_text_report(data, dedup_txt)
        _write_html_report(data, html_out)
        logger.info(f"LLM post-process complete: {dedup_txt.name}, {html_out.name}")
        return dedup_txt, html_out
    except Exception as e:
        logger.warning(f"LLM post-process failed ({e}); generating basic HTML without extra dedupe")
        # Fallback: parse the original text into structured and write HTML + copy text
        data = _fallback_structured_from_text(raw)
        dedup_txt = text_report_path.with_name("threat_intel_report_dedup.txt")
        html_out = text_report_path.with_name("threat_intel_report.html")
        # Reuse same structure (minimal dedupe)
        _write_text_report(data, dedup_txt)
        _write_html_report(data, html_out)
        return dedup_txt, html_out

async def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Threat Intelligence RSS Feed Analyzer")
    parser.add_argument(
        "--analyze",
        action="store_true",
        help="Analyze RSS feeds and generate CSV files with extracted IoCs and summaries.",
    )
    parser.add_argument(
        "--generate-report",
        action="store_true",
        help="Generate a categorized report from the analysis CSV file.",
    )
    parser.add_argument(
        "--input-csv",
        type=str,
        default="threat_intel_analysis.csv",
        help="Path to the input CSV file for generating the report (default: threat_intel_analysis.csv).",
    )
    parser.add_argument(
        "--output-report",
        type=str,
        default="threat_intel_report.txt",
        help="Path to the output report file (default: threat_intel_report.txt).",
    )
    args = parser.parse_args()

    # Default behavior: if no flags passed, run analyze AND generate-report with defaults
    if not (args.analyze or args.generate_report):
        logger.info("No flags provided. Running analyze and generate-report with defaults.")
        args.analyze = True
        args.generate_report = True

    generated_csv = None

    if args.analyze:
        logger.info("Analyzing RSS feeds...")
        rss_feeds = load_rss_feeds('rss_feeds.txt')
        if not rss_feeds:
            logger.error("No RSS feeds loaded. Please create rss_feeds.txt with feed URLs.")
            return
        async with ThreatIntelAnalyzer(allow_insecure_fallback=True, skip_ssl_verify=SKIP_SSL_VERIFY) as analyzer:
            generated_csv = await analyzer.analyze_feeds(rss_feeds)

    if args.generate_report:
        logger.info("Generating report...")
        # Prefer the CSV we just generated (stable file), otherwise use provided path
        input_csv = generated_csv if generated_csv else args.input_csv
        input_csv_path = Path(input_csv)
        if not input_csv_path.exists():
            logger.error(f"Input CSV file '{input_csv_path}' not found. Please run the analyzer first.")
            return
        # Write the report into the same newsletter folder as the analysis CSV
        report_name = Path(args.output_report).name
        output_report_path = input_csv_path.parent / report_name
        generate_report(str(input_csv_path), str(output_report_path))
        logger.info(f"Report saved to {output_report_path}")

        # NEW: Send the text report to LLM to dedupe again and produce HTML with clickable links
        dedup_txt, html_out = postprocess_report_with_llm(output_report_path)
        if dedup_txt:
            logger.info(f"Deduplicated text report: {dedup_txt}")
        if html_out:
            logger.info(f"HTML report: {html_out}")

    logger.info("Main function execution completed.")

if __name__ == "__main__":
    # Create sample RSS feeds file if it doesn't exist
    if not Path('rss_feeds.txt').exists():
        sample_feeds = [
            "# Threat Intelligence RSS Feeds",
            "https://feeds.feedburner.com/TheHackersNews",
            "https://krebsonsecurity.com/feed/",
            "https://blog.malwarebytes.com/feed/",
            "https://www.bleepingcomputer.com/feed/",
            "https://threatpost.com/feed/",
            "https://www.darkreading.com/rss/all.xml",
            "https://cybersecuritynews.com/feed/",
            "https://www.securityweek.com/feed/",
            "https://www.infosecurity-magazine.com/rss/news/",
            "https://www.bankinfosecurity.com/rss/topic-321.xml"
        ]
        with open('rss_feeds.txt', 'w') as f:
            f.write('\n'.join(sample_feeds))
        print("Created sample rss_feeds.txt file. Add more RSS feed URLs to this file.")

    asyncio.run(main())
