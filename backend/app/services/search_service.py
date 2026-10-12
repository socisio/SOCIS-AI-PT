"""
SOCIS-AI-PT — Search Service
Extended from original search.py — Web search via DuckDuckGo + CVE/NVD lookup.
"""

import re
from typing import List, Dict, Optional
from duckduckgo_search import DDGS

from app.config import settings


class SearchService:
    """Web search and CVE/NVD lookup service."""

    # ─── DuckDuckGo Web Search ────────────────────────────────

    def search_web(self, query: str, max_results: int = 5) -> List[Dict]:
        """Search the web using DuckDuckGo."""
        try:
            results = []
            with DDGS() as ddgs:
                for r in ddgs.text(query, max_results=max_results):
                    results.append({
                        "title": r.get("title", ""),
                        "url": r.get("href", ""),
                        "snippet": r.get("body", ""),
                    })
            return results
        except Exception as e:
            return [{"title": "Search Error", "url": "", "snippet": str(e)}]

    def format_search_results(self, results: List[Dict]) -> str:
        """Format search results as a text block for LLM context."""
        if not results:
            return "[No search results found]"
        output = ""
        for i, r in enumerate(results, 1):
            output += f"\n[{i}] {r['title']}\nURL: {r['url']}\n{r['snippet']}\n"
        return output

    # ─── CVE / NVD Lookup ────────────────────────────────────

    async def lookup_cve(self, cve_id: str) -> Dict:
        """Fetch CVE details from NVD API v2."""
        import httpx
        cve_id = cve_id.strip().upper()
        if not re.match(r'^CVE-\d{4}-\d+$', cve_id):
            return {"error": f"Invalid CVE ID format: {cve_id}"}

        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(url, headers={"User-Agent": "SOCIS-AI-PT/1.0"})
                resp.raise_for_status()
                data = resp.json()

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return {"cve_id": cve_id, "error": "CVE not found in NVD"}

            cve_data = vulns[0].get("cve", {})
            descriptions = cve_data.get("descriptions", [])
            description = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description")

            # Extract CVSS score
            metrics = cve_data.get("metrics", {})
            cvss_score = None
            severity = "unknown"
            for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if version_key in metrics:
                    cvss_data = metrics[version_key][0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                    severity = cvss_data.get("baseSeverity", "unknown").lower()
                    break

            published = cve_data.get("published", "")
            modified = cve_data.get("lastModified", "")

            # References
            references = [r["url"] for r in cve_data.get("references", [])[:5]]

            return {
                "cve_id": cve_id,
                "description": description,
                "cvss_score": cvss_score,
                "severity": severity,
                "published": published,
                "modified": modified,
                "references": references,
            }
        except httpx.HTTPError as e:
            return {"cve_id": cve_id, "error": f"HTTP error: {str(e)}"}
        except Exception as e:
            return {"cve_id": cve_id, "error": str(e)}

    async def search_cves(self, keyword: str, max_results: int = 10) -> List[Dict]:
        """Search NVD for CVEs matching a keyword."""
        import httpx
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage={max_results}"
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.get(url, headers={"User-Agent": "SOCIS-AI-PT/1.0"})
                resp.raise_for_status()
                data = resp.json()

            results = []
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                descriptions = cve.get("descriptions", [])
                description = next((d["value"] for d in descriptions if d["lang"] == "en"), "")[:300]

                metrics = cve.get("metrics", {})
                cvss_score = None
                for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if version_key in metrics:
                        cvss_score = metrics[version_key][0].get("cvssData", {}).get("baseScore")
                        break

                results.append({
                    "cve_id": cve_id,
                    "description": description,
                    "cvss_score": cvss_score,
                    "published": cve.get("published", ""),
                })
            return results
        except Exception as e:
            return [{"error": str(e)}]

    # ─── ExploitDB Search ────────────────────────────────────

    def search_exploitdb(self, query: str, max_results: int = 5) -> List[Dict]:
        """Search ExploitDB via DuckDuckGo (site:exploit-db.com)."""
        site_query = f"site:exploit-db.com {query}"
        results = self.search_web(site_query, max_results=max_results)
        exploits = []
        for r in results:
            if "exploit-db.com" in r.get("url", ""):
                exploits.append({
                    "title": r["title"],
                    "url": r["url"],
                    "description": r["snippet"],
                    "source": "exploit-db",
                })
        return exploits

    # ─── Port/Service CVE Search ─────────────────────────────

    async def search_service_cves(self, service_name: str, version: str = None) -> List[Dict]:
        """Search for CVEs affecting a specific service/version."""
        query = f"{service_name} {version or ''}".strip()
        return await self.search_cves(query, max_results=5)


# Singleton
search_service = SearchService()
