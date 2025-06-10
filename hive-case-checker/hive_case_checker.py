#!/usr/bin/env python3
"""
TheHive Case Analysis Checker Script

This script continuously monitors TheHive cases and checks if all observables
have been analyzed by all compatible Cortex analyzers. It tags cases as 'analyzed'
when all observables are fully analyzed, and keeps monitoring partially analyzed cases.
Cases with no observables are completely skipped from processing.
"""

import time
import logging
from datetime import datetime
from typing import List, Dict, Set, Optional
import requests
import json

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/hive-checker.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class HiveCaseChecker:
    def __init__(self, hive_url: str, hive_api_key: str, cortex_url: str, cortex_api_key: str):
        self.hive_url = hive_url.rstrip('/')
        self.hive_api_key = hive_api_key
        self.cortex_url = cortex_url.rstrip('/')
        self.cortex_api_key = cortex_api_key
        
        self.hive_headers = {
            'Authorization': f'Bearer {hive_api_key}',
            'Content-Type': 'application/json'
        }
        
        self.cortex_headers = {
            'Authorization': f'Bearer {cortex_api_key}',
            'Content-Type': 'application/json'
        }
        
        self.available_analyzers = {}
        self.analyzer_datatypes = {}
        
    def test_connections(self):
        logger.info("Testing connections...")
        
        try:
            query = {"query": [{"_name": "listCase", "range": "0-1"}]}
            response = requests.post(
                f'{self.hive_url}/api/v1/query',
                headers=self.hive_headers,
                json=query,
                timeout=10
            )
            if response.status_code == 200:
                logger.info("TheHive connection successful")
            else:
                logger.error(f"TheHive connection failed: {response.status_code} - {response.text}")
        except Exception as e:
            logger.error(f"TheHive connection error: {e}")
        
        logger.info("Testing Cortex connection...")
        
        try:
            response = requests.post(
                f'{self.cortex_url}/api/analyzer/_search',
                headers={'Authorization': f'Bearer {self.cortex_api_key}', 'Content-Type': 'application/json'},
                json={"query":{}},
                timeout=10
            )
            logger.info(f"Cortex analyzer endpoint: {response.status_code}")
            if response.status_code == 200:
                analyzers = response.json()
                logger.info(f"Cortex connection successful. Found {len(analyzers)} analyzers")
                return True
            else:
                logger.error(f"Cortex analyzer endpoint failed: {response.text[:200]}")
        except Exception as e:
            logger.error(f"Cortex analyzer endpoint error: {e}")
        
        return False
        
    def get_available_analyzers(self) -> Dict:
        try:
            response = requests.post(
                f'{self.cortex_url}/api/analyzer/_search',
                headers=self.cortex_headers,
                json={"query":{}},
                timeout=30
            )
            
            if response.status_code == 200:
                analyzers = response.json()
                self.available_analyzers = {analyzer['name']: analyzer for analyzer in analyzers}
                
                self.analyzer_datatypes = {}
                for analyzer in analyzers:
                    for datatype in analyzer.get('dataTypeList', []):
                        if datatype not in self.analyzer_datatypes:
                            self.analyzer_datatypes[datatype] = []
                        self.analyzer_datatypes[datatype].append(analyzer['name'])
                
                logger.info(f"Found {len(analyzers)} available analyzers")
                logger.info(f"Supported datatypes: {list(self.analyzer_datatypes.keys())}")
                return self.available_analyzers
            else:
                logger.error(f"Failed to get analyzers: {response.status_code} - {response.text}")
                return {}
                
        except Exception as e:
            logger.error(f"Error fetching analyzers: {e}")
            return {}
    
    def get_hive_cases(self, exclude_analyzed: bool = True) -> List[Dict]:
        try:
            query = {"range": "all"}
            
            response = requests.post(
                f'{self.hive_url}/api/case/_search',
                headers=self.hive_headers,
                json=query,
                timeout=30
            )
            response.raise_for_status()
            
            cases = response.json()
            
            filtered_cases = []
            for case in cases:
                status = case.get('status', '').lower()
                if status in ['resolved', 'deleted']:
                    continue
                
                if exclude_analyzed:
                    tags = case.get('tags', [])
                    if 'analyzed' in tags:
                        continue
                
                filtered_cases.append(case)
            
            logger.info(f"Found {len(filtered_cases)} cases to check (total: {len(cases)})")
            return filtered_cases
            
        except Exception as e:
            logger.error(f"Error fetching cases: {e}")
            return []
    
    def get_case_observables(self, case_id: str) -> List[Dict]:
        try:
            query = {
                "query": [
                    {"_name": "getCase", "idOrName": case_id},
                    {"_name": "observables"}
                ]
            }
            
            response = requests.post(
                f'{self.hive_url}/api/v1/query',
                headers=self.hive_headers,
                json=query,
                timeout=30
            )
            response.raise_for_status()
            
            observables = response.json()
            return observables
            
        except Exception as e:
            logger.error(f"Error fetching observables for case {case_id}: {e}")
            return []
    
    def get_observable_jobs(self, observable_id: str) -> List[Dict]:
        try:
            query = {
                "query": [
                    {"_name": "getObservable", "idOrName": observable_id},
                    {"_name": "jobs"}
                ]
            }
            
            response = requests.post(
                f'{self.hive_url}/api/v1/query',
                headers=self.hive_headers,
                json=query,
                timeout=30
            )
            response.raise_for_status()
            
            jobs = response.json()
            return jobs
            
        except Exception as e:
            logger.error(f"Error fetching jobs for observable {observable_id}: {e}")
            return []
    
    def get_compatible_analyzers(self, observable_datatype: str) -> List[str]:
        return self.analyzer_datatypes.get(observable_datatype, [])
    
    def tag_case_as_analyzed(self, case_id: str) -> bool:
        try:
            response = requests.get(
                f'{self.hive_url}/api/case/{case_id}',
                headers=self.hive_headers,
                timeout=30
            )
            response.raise_for_status()
            case_data = response.json()
            
            current_tags = case_data.get('tags', [])
            if 'analyzed' not in current_tags:
                current_tags.append('analyzed')
                
                update_payload = {'tags': current_tags}
                response = requests.patch(
                    f'{self.hive_url}/api/case/{case_id}',
                    headers=self.hive_headers,
                    json=update_payload,
                    timeout=30
                )
                response.raise_for_status()
                
                logger.info(f"Tagged case {case_id} as 'analyzed'")
                return True
            
            return True
            
        except Exception as e:
            logger.error(f"Error tagging case {case_id}: {e}")
            return False
    
    def is_job_completed_successfully(self, job: Dict) -> bool:
        status = job.get('status', '').lower()
        return status == 'success'
    
    def case_has_observables(self, case: Dict) -> bool:
        case_id = case['_id']
        
        try:
            observables = self.get_case_observables(case_id)
            return len(observables) > 0
        except Exception as e:
            logger.error(f"Error checking observables for case {case_id}: {e}")
            return False
    
    def check_case_analysis_status(self, case: Dict) -> str:
        case_id = case['_id']
        case_title = case.get('title', 'Unknown')
        
        logger.info(f"Checking case {case_id}: {case_title}")
        
        observables = self.get_case_observables(case_id)
        
        if not observables:
            logger.warning(f"Case {case_id} unexpectedly has no observables")
            return 'no_observables'
        
        logger.info(f"Case {case_id} has {len(observables)} observables")
        
        all_observables_fully_analyzed = True
        
        for observable in observables:
            observable_id = observable['_id']
            datatype = observable.get('dataType', '')
            data = observable.get('data', '')[:50] + ('...' if len(observable.get('data', '')) > 50 else '')
            
            logger.info(f"  Checking observable {observable_id} ({datatype}: {data})")
            
            compatible_analyzers = self.get_compatible_analyzers(datatype)
            
            if not compatible_analyzers:
                logger.info(f"    No compatible analyzers for datatype '{datatype}' - skipping")
                continue
            
            logger.info(f"    Compatible analyzers: {compatible_analyzers}")
            
            existing_jobs = self.get_observable_jobs(observable_id)
            
            completed_analyzers = set()
            
            for job in existing_jobs:
                if self.is_job_completed_successfully(job):
                    analyzer_name = job.get('analyzerName', '')
                    completed_analyzers.add(analyzer_name)
            
            logger.info(f"    Successfully completed analyzers: {completed_analyzers}")
            
            missing_analyzers = set(compatible_analyzers) - completed_analyzers
            
            if missing_analyzers:
                logger.info(f"    Missing analyzers: {missing_analyzers}")
                all_observables_fully_analyzed = False
            else:
                logger.info(f"    Observable fully analyzed")
        
        if all_observables_fully_analyzed:
            logger.info(f"Case {case_id} is FULLY ANALYZED")
            return 'fully_analyzed'
        else:
            logger.info(f"Case {case_id} is PARTIALLY ANALYZED")
            return 'partially_analyzed'
    
    def run_continuous_check(self, sleep_interval: int = 60):
        logger.info("Starting continuous case checking loop")
        
        if not self.get_available_analyzers():
            logger.error("No analyzers available, exiting")
            return
        
        cycle_count = 0
        
        while True:
            try:
                cycle_count += 1
                logger.info(f"=== Starting check cycle #{cycle_count} ===")
                
                cases = self.get_hive_cases(exclude_analyzed=True)
                
                if not cases:
                    logger.info("No cases to check")
                else:
                    cases_with_observables = []
                    cases_without_observables = 0
                    
                    for case in cases:
                        if self.case_has_observables(case):
                            cases_with_observables.append(case)
                        else:
                            cases_without_observables += 1
                            case_id = case['_id']
                            case_title = case.get('title', 'Unknown')
                            logger.info(f"Skipping case {case_id}: {case_title} - no observables")
                    
                    logger.info(f"Processing {len(cases_with_observables)} cases with observables")
                    if cases_without_observables > 0:
                        logger.info(f"Skipped {cases_without_observables} cases without observables")
                    
                    fully_analyzed_count = 0
                    partially_analyzed_count = 0
                    
                    for case in cases_with_observables:
                        case_id = case['_id']
                        
                        try:
                            status = self.check_case_analysis_status(case)
                            
                            if status == 'fully_analyzed':
                                if self.tag_case_as_analyzed(case_id):
                                    fully_analyzed_count += 1
                            elif status == 'partially_analyzed':
                                partially_analyzed_count += 1
                                
                        except Exception as e:
                            logger.error(f"Error checking case {case_id}: {e}")
                    
                    logger.info(f"Cycle #{cycle_count} summary:")
                    logger.info(f"  Fully analyzed and tagged: {fully_analyzed_count}")
                    logger.info(f"  Partially analyzed (will recheck): {partially_analyzed_count}")
                    if cases_without_observables > 0:
                        logger.info(f"  Cases without observables (skipped): {cases_without_observables}")
                
                logger.info(f"Sleeping for {sleep_interval} seconds...")
                time.sleep(sleep_interval)
                
            except KeyboardInterrupt:
                logger.info("Received interrupt signal, shutting down...")
                break
            except Exception as e:
                logger.error(f"Error in main loop: {e}")
                time.sleep(sleep_interval)


def main():
    # Configuration - Replace with your actual values
    HIVE_URL = "ENTER_YOUR_THEHIVE_URL_HERE"  # Example: "http://your-hive-server:9000"
    HIVE_API_KEY = "ENTER_YOUR_THEHIVE_API_KEY_HERE"
    CORTEX_URL = "ENTER_YOUR_CORTEX_URL_HERE"  # Example: "http://your-cortex-server:9001"
    CORTEX_API_KEY = "ENTER_YOUR_CORTEX_API_KEY_HERE"
    
    # Sleep interval between cycles (seconds)
    SLEEP_INTERVAL = 60
    
    checker = HiveCaseChecker(
        hive_url=HIVE_URL,
        hive_api_key=HIVE_API_KEY,
        cortex_url=CORTEX_URL,
        cortex_api_key=CORTEX_API_KEY
    )
    
    if not checker.test_connections():
        logger.error("Connection tests failed. Please check your configuration.")
        return
    
    checker.run_continuous_check(sleep_interval=SLEEP_INTERVAL)


if __name__ == "__main__":
    main()
