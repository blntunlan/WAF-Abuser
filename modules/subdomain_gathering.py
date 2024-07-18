import asyncio
import datetime
import json
import logging
import os
from itertools import chain
from typing import Set, List

import aiohttp
from bs4 import BeautifulSoup

from modules.utility import get_top_domains

logger = logging.getLogger(__name__)

class SubdomainGatherer:
    def __init__(self, cache_dir: str = '../../cache'):
        self.cache_dir = os.path.normpath(os.path.dirname(os.path.join(os.path.realpath(__file__), cache_dir)))
        self.ensure_cache_dirs()

    def ensure_cache_dirs(self):
        for subdir in ['dnsdumpster_req_logs', 'certspotter_req_logs', 'hackertarget_req_logs', 'crtsh_req_logs']:
            os.makedirs(os.path.join(self.cache_dir, subdir), exist_ok=True)

    async def dnsdumpster_scraping(self, domain: str) -> List[str]:
        async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar()) as session:
            async with session.get('https://dnsdumpster.com') as resp:
                cookies = session.cookie_jar.filter_cookies('https://dnsdumpster.com')
                csrf_token = str(cookies.get('csrftoken')).split('Set-Cookie: csrftoken=')[1]

            async with session.post(
                'https://dnsdumpster.com',
                data={'csrfmiddlewaretoken': csrf_token, 'targetip': domain, 'user': 'free'},
                headers={
                    'Host': 'dnsdumpster.com',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
                    'Referer': 'https://dnsdumpster.com/',
                    'Cookie': f'csrftoken={csrf_token}'
                }
            ) as resp:
                response_text = await resp.text()

        soup = BeautifulSoup(response_text, 'html.parser')
        domains = [
            found_domain.text.split('HTTP')[0].strip('1234567890 .').rstrip('.')
            for found_domain in soup.find_all('td', {'class': 'col-md-4'})
        ]

        self.write_to_cache('dnsdumpster_req_logs', domain, response_text, domains)
        return domains

    async def certspotter_scraping(self, domain: str) -> Set[str]:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f'https://api.certspotter.com/v1/issuances?domain={domain}&expand=dns_names',
                headers={'Accept': 'application/json'}
            ) as resp:
                response_json = await resp.json(encoding='utf-8')

        domains = {
            dns_name.lstrip('*.')
            for item in response_json
            for dns_name in item['dns_names']
        }

        self.write_to_cache('certspotter_req_logs', domain, json.dumps(response_json, indent=2), domains)
        return domains

    async def hackertarget_scraping(self, domain: str) -> Set[str]:
        async with aiohttp.ClientSession() as session:
            async with session.get(f'https://api.hackertarget.com/hostsearch/?q={domain}') as resp:
                response_text = await resp.text(encoding='utf-8')

        if 'API count exceeded' in response_text:
            logger.warning('SKIP HackerTarget | Daily Limit Exceeded. (Possible bypass: new IP or use hackertarget.com API Key)')
            return set()

        domains = {line.split(',')[0] for line in response_text.splitlines()}
        self.write_to_cache('hackertarget_req_logs', domain, response_text, domains)
        return domains

    async def crtsh_scraping(self, domain: str) -> Set[str]:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f'https://crt.sh/?q={domain}&output=json',
                headers={'Accept': 'application/json'}
            ) as resp:
                response_json = await resp.json(encoding='utf-8')

        domains = {
            name for item in response_json
            for name in item['name_value'].split('\n')
            if not name.startswith('*.')
        }

        self.write_to_cache('crtsh_req_logs', domain, json.dumps(response_json, indent=2), domains)
        return domains

    def write_to_cache(self, subdir: str, domain: str, response: str, domains: Set[str]):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        cache_path = os.path.join(self.cache_dir, subdir)

        with open(os.path.join(cache_path, f'{domain}_{timestamp}_response.txt'), 'w') as f:
            f.write(response)

        with open(os.path.join(cache_path, f'{domain}_{timestamp}_domains.txt'), 'w') as f:
            f.write('\n'.join(sorted(domains)))

    async def gather_subdomains(self, domains: Set[str]) -> Set[str]:
        all_domains = set()

        for domain in domains:
            subdomains = set()
            tasks = [
                self.dnsdumpster_scraping(domain),
                self.certspotter_scraping(domain),
                self.hackertarget_scraping(domain),
                self.crtsh_scraping(domain),
                get_top_domains([domain])
            ]

            results = await asyncio.gather(*tasks)
            for result in results:
                subdomains.update(result)

            subdomains.add(domain)
            all_domains.update(subdomains)

            self.write_subdomain_results(domain, subdomains)

        self.write_all_domains(all_domains)
        return all_domains

    def write_subdomain_results(self, domain: str, subdomains: Set[str]):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f'{domain}_{timestamp}_subdomains.txt'
        with open(os.path.join(self.cache_dir, filename), 'w') as f:
            f.write('\n'.join(sorted(subdomains)))

    def write_all_domains(self, all_domains: Set[str]):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f'ALL_DOMAINS_{timestamp}.txt'
        with open(os.path.join(self.cache_dir, filename), 'w') as f:
            f.write('\n'.join(sorted(all_domains)))

async def main(domains: Set[str]):
    gatherer = SubdomainGatherer()
    all_domains = await gatherer.gather_subdomains(domains)
    return sorted(all_domains)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    input_domains = {"example.com", "example.org"}  # Replace with actual domains
    asyncio.run(main(input_domains))
