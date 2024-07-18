import asyncio
import ipaddress
import logging
from itertools import chain
from typing import List, Set, Tuple, Optional

import aiohttp
import tldextract
from html_similarity import similarity
from pathlib import Path

logger = logging.getLogger(__name__)

class UtilityFunctions:
    def __init__(self, cache_dir: str = '../../cache', data_dir: str = '../data'):
        self.cache_dir = Path(__file__).parent.parent.parent / cache_dir
        self.data_dir = Path(__file__).parent.parent / data_dir
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def get_page_content(self, url: str) -> Optional[str]:
        if not self.session:
            raise RuntimeError("Session not initialized. Use 'async with' to create an instance.")
        try:
            async with self.session.get(f"https://{url}", ssl=False, timeout=3) as response:
                return await response.text()
        except (aiohttp.ClientConnectorError, asyncio.TimeoutError) as e:
            logger.info(f'Skipped | Error with {url}: {str(e)}')
            return None

    async def compare_two_pages(self, original_content: str, check_url: str) -> Tuple[str, int]:
        check_content = await self.get_page_content(check_url)
        if not check_content:
            return check_url, 0
        similarity_score = int(similarity(original_content, check_content, k=0.3) * 100)
        return check_url, similarity_score

    async def parse_public_waf_ranges(self) -> List[str]:
        waf_file = self.data_dir / 'PublicWAFs.txt'
        async with aiofiles.open(waf_file, mode='r') as file:
            content = await file.read()
        return [ip.strip() for ip in content.splitlines()[1:]]

    async def filter_out_waf_ips(self, ips_to_check: Set[str]) -> Set[str]:
        waf_ips_with_cidr = await self.parse_public_waf_ranges()
        all_waf_ips = set(chain.from_iterable(ipaddress.ip_network(waf_ip) for waf_ip in waf_ips_with_cidr))
        return {ip for ip in ips_to_check if ipaddress.ip_address(ip) not in all_waf_ips}

    async def get_top_domains(self, domains: List[str]) -> List[str]:
        domains = list(filter(None, domains))
        tld_cache = self.cache_dir / 'tldextract-cache'
        custom_tldextract = tldextract.TLDExtract(cache_dir=str(tld_cache))
        
        def extract_domain(domain: str) -> str:
            extracted = custom_tldextract(domain)
            return f"{extracted.domain}.{extracted.suffix}"

        return [extract_domain(domain) for domain in domains]

async def main():
    logging.basicConfig(level=logging.INFO)
    
    async with UtilityFunctions() as utils:
        # Example usage
        content = await utils.get_page_content("example.com")
        if content:
            comparison = await utils.compare_two_pages(content, "example.org")
            print(f"Comparison result: {comparison}")

        ips_to_check = {"192.0.2.1", "198.51.100.1", "203.0.113.1"}
        filtered_ips = await utils.filter_out_waf_ips(ips_to_check)
        print(f"Filtered IPs: {filtered_ips}")

        domains = ["example.com", "sub.example.co.uk", "invalid..domain"]
        top_domains = await utils.get_top_domains(domains)
        print(f"Top domains: {top_domains}")

if __name__ == "__main__":
    asyncio.run(main())
