import logging
import json
import requests
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatIntelligenceService:
    def __init__(self, cache_file_path="backend/threat_data_cache.json"):
        self.cache_file_path = cache_file_path
        self.cache = self._load_cache()
        # Ensure default subscription statuses are set if not present
        self._initialize_feed_metadata()
        if not self.cache.get('osint_feed') and not self.cache.get('cve_feed'): # If main data feeds are empty
            self.initial_data_load()


    def _initialize_feed_metadata(self):
        """Initializes metadata like subscription status for feeds if not already present."""
        changed = False
        if 'threatfox_meta' not in self.cache:
            self.cache['threatfox_meta'] = {'is_subscribed': True, 'name': 'ThreatFox IOCs', 'id': 'threatfox'}
            changed = True
        if 'cve_circl_meta' not in self.cache:
            self.cache['cve_circl_meta'] = {'is_subscribed': True, 'name': 'CIRCL CVEs', 'id': 'cve_circl'}
            changed = True
        if changed:
            self._save_cache(self.cache)

    def _load_cache(self):
        try:
            with open(self.cache_file_path, 'r') as f:
                cache_data = json.load(f)
                logger.info(f"Cache loaded from {self.cache_file_path}")
                return cache_data
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.warning(f"Cache file not found or invalid, attempting to initialize new cache: {e}")
            # Initialize with empty cache and basic metadata structure
            new_cache = {}
            self._save_cache(new_cache) # save empty cache first
            # Now call _initialize_feed_metadata which operates on self.cache
            # self.cache = new_cache # Temporarily set self.cache for _initialize_feed_metadata
            # self._initialize_feed_metadata() # This will save again.
            # Let's simplify: just return empty and let constructor handle init.
            return {}


    def _save_cache(self, data):
        try:
            with open(self.cache_file_path, 'w') as f:
                json.dump(data, f, indent=4)
            logger.info(f"Cache saved to {self.cache_file_path}")
        except IOError as e:
            logger.error(f"Error saving cache to {self.cache_file_path}: {e}")

    def initial_data_load(self):
        logger.info("Performing initial data load for subscribed feeds...")
        if self.cache.get('threatfox_meta', {}).get('is_subscribed', True):
            self.fetch_osint_feed()
        else:
            logger.info("Skipping OSINT feed load as it's not subscribed.")

        if self.cache.get('cve_circl_meta', {}).get('is_subscribed', True):
            self.fetch_cve_data()
        else:
            logger.info("Skipping CVE feed load as it's not subscribed.")
        logger.info("Initial data load process complete.")

    def fetch_osint_feed(self):
        # Ensure that we only fetch if subscribed
        if not self.cache.get('threatfox_meta', {}).get('is_subscribed', True):
            logger.info("ThreatFox feed is unsubscribed. Skipping fetch.")
            return {"status": "skipped", "reason": "unsubscribed", "data": []}

        logger.info("Fetching OSINT feed from ThreatFox...")
        url = "https://threatfox.abuse.ch/export/json/recent/"
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()  # Raise an exception for HTTP errors
            data = response.json()

            # Structure the data (example: take first 50 indicators for brevity)
            # In a real scenario, you might want to process all of them or filter
            structured_data = []
            for item in data[:50]: # Limiting to 50 for this example
                indicator_data = {
                    "ioc_id": item.get("ioc_id"),
                    "indicator": item.get("ioc_value"),
                    "type": item.get("ioc_type"),
                    "threat_type": item.get("threat_type_desc"),
                    "malware": item.get("malware_printable"),
                    "source": "ThreatFox",
                    "first_seen": item.get("first_seen_utc"),
                    "last_seen": item.get("last_seen_utc"),
                    "confidence": item.get("confidence_level"),
                    "reference": item.get("reference"),
                    "tags": item.get("tags")
                }
                structured_data.append(indicator_data)

            self.cache['osint_feed'] = {
                "data": structured_data,
                "last_updated": datetime.utcnow().isoformat(),
                "source_url": url,
                 "name": "ThreatFox IOCs", # Added for consistency
                 "id": "threatfox"
            }
            self._save_cache(self.cache)
            logger.info(f"Successfully fetched and cached OSINT feed. {len(structured_data)} items processed.")
            return self.cache['osint_feed']
        except requests.RequestException as e:
            logger.error(f"Error fetching OSINT feed from {url}: {e}")
            return {"error": str(e), "status": "error", "data": []}
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing JSON from OSINT feed {url}: {e}")
            return {"error": "JSON parsing error", "status": "error", "data": []}
        except Exception as e:
            logger.error(f"An unexpected error occurred while fetching OSINT feed: {e}")
            return {"error": str(e), "status": "error", "data": []}

    def fetch_cve_data(self):
        # Ensure that we only fetch if subscribed
        if not self.cache.get('cve_circl_meta', {}).get('is_subscribed', True):
            logger.info("CIRCL CVE feed is unsubscribed. Skipping fetch.")
            return {"status": "skipped", "reason": "unsubscribed", "data": []}

        logger.info("Fetching CVE data from cve.circl.lu...")
        url = "https://cve.circl.lu/api/last/10"
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()

            structured_data = []
            if isinstance(data, list): # CIRCL API returns a list of CVEs
                for item in data:
                    cve_data = {
                        "id": item.get("id"),
                        "summary": item.get("summary"),
                        "published": item.get("Published"),
                        "modified": item.get("Modified"),
                        "cvss": item.get("cvss"),
                        "references": item.get("references", [])
                    }
                    structured_data.append(cve_data)

            self.cache['cve_feed'] = {
                "data": structured_data,
                "last_updated": datetime.utcnow().isoformat(),
                "source_url": url,
                "name": "CIRCL CVEs", # Added for consistency
                "id": "cve_circl"
            }
            self._save_cache(self.cache)
            logger.info(f"Successfully fetched and cached CVE data. {len(structured_data)} items processed.")
            return self.cache['cve_feed']
        except requests.RequestException as e:
            logger.error(f"Error fetching CVE data from {url}: {e}")
            return {"error": str(e), "status": "error", "data": []}
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing JSON from CVE feed {url}: {e}")
            return {"error": "JSON parsing error", "status": "error", "data": []}
        except Exception as e:
            logger.error(f"An unexpected error occurred while fetching CVE feed: {e}")
            return {"error": str(e), "status": "error", "data": []}

    def get_emerging_threats(self):
        logger.info("Getting emerging threats from subscribed and available feeds...")
        emerging_threats = []

        # CVEs
        cve_meta = self.cache.get('cve_circl_meta', {})
        if cve_meta.get('is_subscribed', True):
            if 'cve_feed' in self.cache and self.cache['cve_feed'].get('data'):
                for cve in self.cache['cve_feed']['data'][:2]: # First 2 as example
                    emerging_threats.append({
                        "type": "CVE",
                        "id": cve.get("id"),
                        "summary": cve.get("summary"),
                        "published": cve.get("published"),
                        "source": "cve.circl.lu"
                    })
            else:
                logger.info("CVE feed data not available for emerging threats (or feed empty).")
        else:
            logger.info("CVE feed is not subscribed, skipping for emerging threats.")

        # OSINT indicators
        osint_meta = self.cache.get('threatfox_meta', {})
        if osint_meta.get('is_subscribed', True):
            if 'osint_feed' in self.cache and self.cache['osint_feed'].get('data'):
                for indicator in self.cache['osint_feed']['data']:
                    if indicator.get("confidence", 0) > 75: # High confidence
                        emerging_threats.append({
                            "type": "OSINT Indicator",
                            "indicator": indicator.get("indicator"),
                            "indicator_type": indicator.get("type"),
                            "threat_type": indicator.get("threat_type"),
                            "source": indicator.get("source"),
                            "last_seen": indicator.get("last_seen")
                        })
                        if len(emerging_threats) >= 5: # Limit total emerging threats
                            break
            else:
                logger.info("OSINT feed data not available for emerging threats (or feed empty).")
        else:
            logger.info("OSINT feed is not subscribed, skipping for emerging threats.")

        logger.info(f"Returning {len(emerging_threats)} emerging threats.")
        return emerging_threats

    def get_feeds(self):
        logger.info("Getting feeds status including subscription info...")
        feeds_status = []

        # ThreatFox OSINT Feed
        osint_meta = self.cache.get('threatfox_meta', {'is_subscribed': True, 'name': 'ThreatFox IOCs', 'id': 'threatfox'}) # Default if meta somehow missing
        osint_data = self.cache.get('osint_feed', {})
        feeds_status.append({
            "id": osint_meta.get('id', 'threatfox'),
            "name": osint_meta.get('name', 'ThreatFox IOCs'),
            "status": "active" if osint_data.get("data") else ("error" if osint_data.get("error") else "pending/unfetched"),
            "entries": len(osint_data.get("data", [])),
            "last_updated": osint_data.get("last_updated"),
            "source_url": osint_data.get("source_url", "https://threatfox.abuse.ch/export/json/recent/"),
            "is_subscribed": osint_meta.get('is_subscribed', True)
        })

        # CIRCL CVE Feed
        cve_meta = self.cache.get('cve_circl_meta', {'is_subscribed': True, 'name': 'CIRCL CVEs', 'id': 'cve_circl'}) # Default if meta somehow missing
        cve_data = self.cache.get('cve_feed', {})
        feeds_status.append({
            "id": cve_meta.get('id', 'cve_circl'),
            "name": cve_meta.get('name', 'CIRCL CVEs'),
            "status": "active" if cve_data.get("data") else ("error" if cve_data.get("error") else "pending/unfetched"),
            "entries": len(cve_data.get("data", [])),
            "last_updated": cve_data.get("last_updated"),
            "source_url": cve_data.get("source_url", "https://cve.circl.lu/api/last/10"),
            "is_subscribed": cve_meta.get('is_subscribed', True)
        })

        return feeds_status

    def update_feed_subscription(self, feed_id: str, is_subscribed: bool):
        logger.info(f"Updating feed subscription for {feed_id} to {is_subscribed}...")
        self.cache = self._load_cache() # Ensure fresh cache

        meta_key = None
        if feed_id == "threatfox":
            meta_key = "threatfox_meta"
        elif feed_id == "cve_circl":
            meta_key = "cve_circl_meta"
        else:
            logger.warning(f"Subscription update requested for unknown feed ID: {feed_id}")
            return {"error": f"Feed ID {feed_id} not found for subscription update."}

        if meta_key not in self.cache: # Should have been initialized by _initialize_feed_metadata
             self.cache[meta_key] = {'id': feed_id, 'name': 'Unknown Feed'} # Basic default

        self.cache[meta_key]['is_subscribed'] = is_subscribed
        self._save_cache(self.cache)

        logger.info(f"Subscription status for {feed_id} set to {is_subscribed}.")

        # If subscribing, fetch data immediately
        if is_subscribed:
            logger.info(f"Fetching data for newly subscribed feed: {feed_id}")
            self.refresh_feed_data(feed_id) # This will also save the cache
        else: # If unsubscribing, we could clear the data, or leave it stale.
            # Current behavior: leave data, it just won't be updated or used for emerging threats.
            logger.info(f"Feed {feed_id} unsubscribed. Data will not be actively refreshed.")

        updated_feed_info = self.get_feeds() # Get the full list to find the specific feed
        for feed_info in updated_feed_info:
            if feed_info['id'] == feed_id:
                return feed_info # Return the updated feed status
        return {"error": "Failed to retrieve updated feed status after subscription change."}


    def refresh_feed_data(self, feed_id: str):
        logger.info(f"Refreshing feed data for {feed_id} if subscribed...")
        feed_meta_key = None
        fetch_function = None

        if feed_id == "threatfox":
            feed_meta_key = "threatfox_meta"
            fetch_function = self.fetch_osint_feed
        elif feed_id == "cve_circl":
            feed_meta_key = "cve_circl_meta"
            fetch_function = self.fetch_cve_data
        else:
            logger.warning(f"Refresh requested for unknown feed ID: {feed_id}")
            return {"feed_id": feed_id, "status": "error", "error": f"Feed ID {feed_id} not recognized for refresh."}

        # Check subscription status from metadata
        if self.cache.get(feed_meta_key, {}).get('is_subscribed', True):
            logger.info(f"Proceeding with refresh for subscribed feed: {feed_id}")
            result = fetch_function() # This function should save the cache

            # Construct response based on fetch result
            if isinstance(result, dict) and result.get("status") == "error":
                 return {"feed_id": feed_id, "status": "error", "error": result.get("error", "Unknown error during fetch"), "last_updated": None}
            elif isinstance(result, dict) and result.get("status") == "skipped":
                 return {"feed_id": feed_id, "status": "skipped", "message": result.get("reason"), "last_updated": None}
            else: # Assuming success
                last_updated_ts = None
                if feed_id == "threatfox" and 'osint_feed' in self.cache:
                    last_updated_ts = self.cache['osint_feed'].get('last_updated')
                elif feed_id == "cve_circl" and 'cve_feed' in self.cache:
                    last_updated_ts = self.cache['cve_feed'].get('last_updated')
                return {"feed_id": feed_id, "status": "refreshed", "last_updated": last_updated_ts, "entry_count": len(result.get("data",[])) if isinstance(result, dict) else None}
        else:
            logger.info(f"Feed {feed_id} is not subscribed. Skipping refresh.")
            return {"feed_id": feed_id, "status": "skipped", "message": "Feed is not subscribed.", "last_updated": None}
