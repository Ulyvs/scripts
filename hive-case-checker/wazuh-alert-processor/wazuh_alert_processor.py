#!/usr/bin/env python3

import time
import json
import logging
import threading
from datetime import datetime, timedelta
from collections import defaultdict
from typing import List, Dict, Any
import requests
from requests.auth import HTTPBasicAuth

# Configuration
THEHIVE_URL = "http://your-thehive-url:9000"
THEHIVE_API_KEY = "enter-your-api-key-here"

# Alert buffers for batch processing
low_alerts_buffer = []
last_low_case_time = datetime.now()

# Medium severity case tracking
current_medium_case_id = None
current_medium_case_start_time = None
current_medium_case_alert_count = 0

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('thehive_automation.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class TheHiveAPI:
    def __init__(self, url: str, api_key: str):
        self.url = url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })

    def get_alerts(self, filters: Dict = None) -> List[Dict]:
        endpoint = f"{self.url}/api/v1/query"
        
        query_body = {
            "query": [
                {"_name": "listAlert"}
            ]
        }
        
        if filters:
            filter_conditions = []
            
            for key, value in filters.items():
                if key == "status" and value:
                    filter_conditions.append({
                        "_field": "status",
                        "_value": value
                    })
                elif key == "source" and value:
                    filter_conditions.append({
                        "_field": "source", 
                        "_value": value
                    })
                elif key == "tags" and value:
                    filter_conditions.append({
                        "_not": {
                            "_field": "tags",
                            "_value": value
                        }
                    })
            
            if filter_conditions:
                if len(filter_conditions) == 1:
                    query_body["query"].append({"_name": "filter", **filter_conditions[0]})
                else:
                    query_body["query"].append({
                        "_name": "filter",
                        "_and": filter_conditions
                    })
        
        try:
            logger.debug(f"Query body: {json.dumps(query_body, indent=2)}")
            response = self.session.post(endpoint, json=query_body, timeout=30)
            
            if response.status_code == 200:
                alerts = response.json()
                logger.info(f"Successfully retrieved {len(alerts)} alerts")
                return alerts
            else:
                logger.error(f"Failed to get alerts: HTTP {response.status_code}")
                logger.error(f"Response: {response.text}")
                return []
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get alerts: {e}")
            return []

    def get_all_alerts_simple(self) -> List[Dict]:
        endpoint = f"{self.url}/api/v1/query"
        
        query_body = {
            "query": [
                {"_name": "listAlert"}
            ]
        }
        
        try:
            response = self.session.post(endpoint, json=query_body, timeout=30)
            if response.status_code == 200:
                alerts = response.json()
                logger.info(f"Retrieved {len(alerts)} total alerts")
                return alerts
            else:
                logger.error(f"Failed to get all alerts: {response.status_code}")
                logger.error(f"Response: {response.text}")
                return []
        except Exception as e:
            logger.error(f"Error getting all alerts: {e}")
            return []

    def get_unprocessed_alerts(self) -> List[Dict]:
        endpoint = f"{self.url}/api/v1/query"
        
        query_body = {
            "query": [
                {"_name": "listAlert"},
                {
                    "_name": "filter",
                    "_and": [
                        {
                            "_field": "status",
                            "_value": "New"
                        },
                        {
                            "_field": "source",
                            "_value": "wazuh"
                        },
                        {
                            "_not": {
                                "_field": "tags",
                                "_value": "in-case"
                            }
                        }
                    ]
                }
            ]
        }
        
        try:
            logger.debug(f"Unprocessed alerts query: {json.dumps(query_body, indent=2)}")
            response = self.session.post(endpoint, json=query_body, timeout=30)
            
            if response.status_code == 200:
                alerts = response.json()
                logger.info(f"Found {len(alerts)} unprocessed alerts")
                return alerts
            else:
                logger.error(f"Failed to get unprocessed alerts: {response.status_code}")
                return self._filter_alerts_manually()
                
        except Exception as e:
            logger.error(f"Error getting unprocessed alerts: {e}")
            return self._filter_alerts_manually()

    def _filter_alerts_manually(self) -> List[Dict]:
        all_alerts = self.get_all_alerts_simple()
        unprocessed = []
        
        for alert in all_alerts:
            status = alert.get('status', '').lower()
            source = alert.get('source', '').lower()
            tags = alert.get('tags', [])
            
            if (status == 'new' and 
                source == 'wazuh' and 
                'in-case' not in [tag.lower() for tag in tags]):
                unprocessed.append(alert)
        
        logger.info(f"Manually filtered to {len(unprocessed)} unprocessed alerts")
        return unprocessed

    def create_case(self, case_data: Dict) -> Dict:
        endpoint = f"{self.url}/api/v1/case"
        
        try:
            response = self.session.post(endpoint, json=case_data, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to create case: {e}")
            return {}

    def promote_alert_to_case(self, alert_id: str, case_template: str = None) -> Dict:
        endpoint = f"{self.url}/api/v1/alert/{alert_id}/case"
        data = {}
        if case_template:
            data['caseTemplate'] = case_template
            
        try:
            response = self.session.post(endpoint, json=data, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to promote alert {alert_id} to case: {e}")
            return {}

    def merge_alert_into_case(self, alert_id: str, case_id: str) -> bool:
        endpoint = f"{self.url}/api/alert/{alert_id}/merge/{case_id}"
        
        try:
            response = self.session.post(endpoint, timeout=30)
            if response.status_code == 200:
                logger.info(f"Successfully merged alert {alert_id} into case {case_id}")
                return True
            else:
                logger.warning(f"Merge failed with status {response.status_code}, trying alternative method")
                return self._import_alert_into_case(alert_id, case_id)
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to merge alert {alert_id} into case {case_id}: {e}")
            return self._import_alert_into_case(alert_id, case_id)

    def _import_alert_into_case(self, alert_id: str, case_id: str) -> bool:
        endpoint = f"{self.url}/api/v1/case/{case_id}/alert/{alert_id}"
        
        try:
            response = self.session.post(endpoint, timeout=30)
            if response.status_code in [200, 201]:
                logger.info(f"Successfully imported alert {alert_id} into case {case_id}")
                return True
            else:
                logger.error(f"Failed to import alert {alert_id} into case {case_id}: HTTP {response.status_code}")
                logger.debug(f"Response: {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to import alert {alert_id} into case {case_id}: {e}")
            return False

    def update_alert_tags(self, alert_id: str, tags: List[str]) -> bool:
        endpoint = f"{self.url}/api/v1/alert/{alert_id}"
        data = {'tags': tags}
        
        try:
            response = self.session.patch(endpoint, json=data, timeout=30)
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to update alert {alert_id} tags: {e}")
            return False

    def get_case_details(self, case_id: str) -> Dict:
        endpoint = f"{self.url}/api/v1/case/{case_id}"
        
        try:
            response = self.session.get(endpoint, timeout=30)
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Case {case_id} not found: HTTP {response.status_code}")
                return {}
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get case {case_id}: {e}")
            return {}

def extract_observables_from_alert(alert: Dict) -> List[Dict]:
    observables = []
    seen_observables = set()
    
    details = alert.get('details', {})
    agent_ip = None
    if isinstance(details, dict):
        agent_fields = ['agent_ip', 'manager_host', 'agent.ip']
        for field in agent_fields:
            if field in details and details[field]:
                agent_ip = details[field]
                break
    
    if 'observables' in alert:
        for obs in alert['observables']:
            data = obs.get('data', '').strip()
            data_type = obs.get('dataType', 'other')
            
            if not data or data == agent_ip:
                continue
                
            obs_key = f"{data_type}:{data.lower()}"
            
            if obs_key not in seen_observables:
                seen_observables.add(obs_key)
                observables.append({
                    'dataType': data_type,
                    'data': data,
                    'message': obs.get('message', f'{data_type} from alert'),
                    'tags': obs.get('tags', ['wazuh', 'auto-extracted'])
                })
    
    if isinstance(details, dict):
        ip_fields = ['sourceIp', 'destinationIp', 'srcip', 'dstip', 'src_ip', 'dst_ip']
        for field in ip_fields:
            if field in details and details[field]:
                ip_value = str(details[field]).strip()
                
                if (ip_value == agent_ip or 
                    ip_value.startswith('127.') or 
                    ip_value.startswith('10.') or
                    ip_value.startswith('192.168.') or
                    ip_value.startswith('172.')):
                    continue
                
                obs_key = f"ip:{ip_value.lower()}"
                if obs_key not in seen_observables:
                    seen_observables.add(obs_key)
                    observables.append({
                        'dataType': 'ip',
                        'data': ip_value,
                        'message': f'{field} from Wazuh alert',
                        'tags': ['wazuh', 'auto-extracted']
                    })
        
        domain_fields = ['domain', 'hostname', 'fqdn']
        for field in domain_fields:
            if field in details and details[field]:
                domain_value = str(details[field]).strip()
                
                if domain_value in ['localhost', 'localhost.localdomain'] or not domain_value:
                    continue
                    
                obs_key = f"domain:{domain_value.lower()}"
                if obs_key not in seen_observables:
                    seen_observables.add(obs_key)
                    observables.append({
                        'dataType': 'domain',
                        'data': domain_value,
                        'message': f'{field} from Wazuh alert',
                        'tags': ['wazuh', 'auto-extracted']
                    })
        
        hash_fields = ['md5', 'sha1', 'sha256', 'file_hash']
        for field in hash_fields:
            if field in details and details[field]:
                hash_value = str(details[field]).strip()
                
                if len(hash_value) >= 32:
                    obs_key = f"hash:{hash_value.lower()}"
                    if obs_key not in seen_observables:
                        seen_observables.add(obs_key)
                        observables.append({
                            'dataType': 'hash',
                            'data': hash_value,
                            'message': f'{field} from Wazuh alert',
                            'tags': ['wazuh', 'auto-extracted']
                        })
        
        url_fields = ['url', 'uri', 'request_uri']
        for field in url_fields:
            if field in details and details[field]:
                url_value = str(details[field]).strip()
                
                if url_value.startswith(('http://', 'https://', 'ftp://')):
                    obs_key = f"url:{url_value.lower()}"
                    if obs_key not in seen_observables:
                        seen_observables.add(obs_key)
                        observables.append({
                            'dataType': 'url',
                            'data': url_value,
                            'message': f'{field} from Wazuh alert',
                            'tags': ['wazuh', 'auto-extracted']
                        })
    
    logger.debug(f"Extracted {len(observables)} unique observables from alert {alert.get('_id')}")
    return observables

def get_alert_severity(alert: Dict) -> str:
    if 'severity' in alert:
        severity_value = alert['severity']
        if isinstance(severity_value, int):
            if severity_value >= 3:
                return 'high'
            elif severity_value == 2:
                return 'medium'
            else:
                return 'low'
    
    details = alert.get('details', {})
    if isinstance(details, dict) and 'rule' in details:
        rule = details['rule']
        if isinstance(rule, dict) and 'level' in rule:
            level = rule['level']
            if isinstance(level, (int, float)):
                if level >= 10:
                    return 'high'
                elif level >= 5:
                    return 'medium'
                else:
                    return 'low'
    
    return 'medium'

def generate_case_description(alerts: List[Dict], severity: str) -> str:
    if not alerts:
        return "Automated case creation from Wazuh alerts"
    
    description_parts = [
        f"# Automated Case - {severity.upper()} Severity",
        f"**Created:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Alert Count:** {len(alerts)}",
        f"**Severity Level:** {severity.upper()}",
        "",
        "## Alert Summary",
        ""
    ]
    
    for i, alert in enumerate(alerts, 1):
        alert_id = alert.get('_id', 'Unknown')
        title = alert.get('title', 'No title')
        source = alert.get('source', 'Unknown')
        
        description_parts.extend([
            f"### Alert {i}: {title}",
            f"**ID:** {alert_id}",
            f"**Source:** {source}",
            ""
        ])
    
    return "\n".join(description_parts)

def create_case_from_alerts(api: TheHiveAPI, alerts: List[Dict], severity: str) -> str:
    if not alerts:
        return None
    
    primary_alert = alerts[0]
    
    case = api.promote_alert_to_case(primary_alert['_id'])
    
    if not case or '_id' not in case:
        logger.error(f"Failed to create case from alert {primary_alert['_id']}")
        return None
    
    case_id = case['_id']
    logger.info(f"Created case {case_id} from primary alert {primary_alert['_id']}")
    
    case_details = api.get_case_details(case_id)
    if not case_details:
        logger.error(f"Cannot verify case {case_id} exists, skipping merge operations")
        return case_id
    
    if len(alerts) > 1:
        success_count = 0
        failed_alerts = []
        
        for alert in alerts[1:]:
            alert_id = alert['_id']
            logger.info(f"Attempting to merge alert {alert_id} into case {case_id}")
            
            if api.merge_alert_into_case(alert_id, case_id):
                success_count += 1
                logger.info(f"Successfully processed alert {alert_id}")
            else:
                failed_alerts.append(alert_id)
                logger.warning(f"Failed to merge alert {alert_id}")
        
        logger.info(f"Successfully merged {success_count}/{len(alerts)-1} additional alerts into case {case_id}")
        
        if failed_alerts:
            logger.warning(f"Failed to merge alerts: {failed_alerts}")
    
    for alert in alerts:
        current_tags = alert.get('tags', [])
        if 'in-case' not in current_tags:
            current_tags.append('in-case')
            api.update_alert_tags(alert['_id'], current_tags)
    
    logger.info(f"Case {case_id} created and tagged {len(alerts)} alerts as processed")
    return case_id

def process_high_severity_alerts(api: TheHiveAPI, alerts: List[Dict]):
    for alert in alerts:
        case_id = create_case_from_alerts(api, [alert], 'high')
        if case_id:
            logger.info(f"Created immediate case {case_id} for high severity alert {alert['_id']}")

def process_medium_severity_alerts(api: TheHiveAPI, alerts: List[Dict]):
    global current_medium_case_id, current_medium_case_start_time, current_medium_case_alert_count
    
    if not alerts:
        return
    
    current_time = datetime.now()
    
    for alert in alerts:
        alert_id = alert['_id']
        
        need_new_case = (
            current_medium_case_id is None or
            current_medium_case_alert_count >= 15 or
            (current_medium_case_start_time and 
             current_time - current_medium_case_start_time >= timedelta(minutes=30))
        )
        
        if need_new_case:
            case_id = create_case_from_alerts(api, [alert], 'medium')
            if case_id:
                current_medium_case_id = case_id
                current_medium_case_start_time = current_time
                current_medium_case_alert_count = 1
                logger.info(f"Created new medium case {case_id} with alert {alert_id}")
            else:
                logger.error(f"Failed to create medium case for alert {alert_id}")
        else:
            if api.merge_alert_into_case(alert_id, current_medium_case_id):
                current_medium_case_alert_count += 1
                logger.info(f"Merged alert {alert_id} into existing case {current_medium_case_id} (count: {current_medium_case_alert_count}/15)")
                
                current_tags = alert.get('tags', [])
                if 'in-case' not in current_tags:
                    current_tags.append('in-case')
                    api.update_alert_tags(alert_id, current_tags)
            else:
                logger.error(f"Failed to merge alert {alert_id} into case {current_medium_case_id}, creating new case")
                case_id = create_case_from_alerts(api, [alert], 'medium')
                if case_id:
                    current_medium_case_id = case_id
                    current_medium_case_start_time = current_time
                    current_medium_case_alert_count = 1
                    logger.info(f"Created fallback medium case {case_id} with alert {alert_id}")

def process_low_severity_alerts(api: TheHiveAPI, alerts: List[Dict]):
    global low_alerts_buffer, last_low_case_time
    
    low_alerts_buffer.extend(alerts)
    
    current_time = datetime.now()
    time_since_last_case = current_time - last_low_case_time
    
    if len(low_alerts_buffer) > 0 and time_since_last_case >= timedelta(hours=24):
        case_id = create_case_from_alerts(api, low_alerts_buffer, 'low')
        if case_id:
            logger.info(f"Created daily case {case_id} for {len(low_alerts_buffer)} low severity alerts")
        
        low_alerts_buffer = []
        last_low_case_time = current_time

def monitor_alerts():
    api = TheHiveAPI(THEHIVE_URL, THEHIVE_API_KEY)
    
    logger.info("Starting TheHive 5.x alert monitoring...")
    
    consecutive_errors = 0
    max_consecutive_errors = 5
    
    while True:
        try:
            alerts = api.get_unprocessed_alerts()
            
            consecutive_errors = 0
            
            if alerts:
                logger.info(f"Processing {len(alerts)} unprocessed alerts")
                
                alerts_by_severity = defaultdict(list)
                
                for alert in alerts:
                    severity = get_alert_severity(alert)
                    alerts_by_severity[severity].append(alert)
                    logger.debug(f"Alert {alert.get('_id')} classified as {severity} severity")
                
                if alerts_by_severity['high']:
                    logger.info(f"Processing {len(alerts_by_severity['high'])} high severity alerts")
                    process_high_severity_alerts(api, alerts_by_severity['high'])
                
                if alerts_by_severity['medium']:
                    logger.info(f"Processing {len(alerts_by_severity['medium'])} medium severity alerts")
                    process_medium_severity_alerts(api, alerts_by_severity['medium'])
                
                if alerts_by_severity['low']:
                    logger.info(f"Adding {len(alerts_by_severity['low'])} low severity alerts to buffer")
                    process_low_severity_alerts(api, alerts_by_severity['low'])
            else:
                logger.info("No unprocessed alerts found")
            
            process_low_severity_alerts(api, [])
            
        except Exception as e:
            consecutive_errors += 1
            logger.error(f"Error in monitoring loop (attempt {consecutive_errors}/{max_consecutive_errors}): {e}")
            
            if consecutive_errors >= max_consecutive_errors:
                logger.critical(f"Too many consecutive errors ({consecutive_errors}), pausing for 5 minutes")
                time.sleep(300)
                consecutive_errors = 0
        
        logger.info("Waiting 60 seconds before next check...")
        time.sleep(60)

if __name__ == "__main__":
    try:
        monitor_alerts()
    except KeyboardInterrupt:
        logger.info("Shutting down alert monitor...")
        if low_alerts_buffer:
            api = TheHiveAPI(THEHIVE_URL, THEHIVE_API_KEY)
            
            if low_alerts_buffer:
                try:
                    case_id = create_case_from_alerts(api, low_alerts_buffer, 'low')
                    if case_id:
                        logger.info(f"Created final case {case_id} for {len(low_alerts_buffer)} low alerts")
                except Exception as e:
                    logger.error(f"Failed to create final low case: {e}")
        
        logger.info("Shutdown complete")
