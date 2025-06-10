#!/usr/bin/env python3

import requests
import json
import os
import time
from datetime import datetime
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch

class TheHiveCaseAnalyzer:
    def __init__(self, hive_url, hive_api_key, cortex_url, cortex_api_key):
        self.hive_url = hive_url
        self.hive_api_key = hive_api_key
        self.cortex_url = cortex_url
        self.cortex_api_key = cortex_api_key
        self.hive_headers = {
            "Authorization": f"Bearer {hive_api_key}",
            "Content-Type": "application/json"
        }
        self.cortex_headers = {
            "Authorization": f"Bearer {cortex_api_key}",
            "Content-Type": "application/json"
        }
        
        self.reports_dir = "case_reports"
        os.makedirs(self.reports_dir, exist_ok=True)

    def get_analyzed_cases_without_report(self):
        query = {
            "query": [
                {
                    "_name": "listCase",
                    "extraData": ["tags"]
                }
            ]
        }
        
        try:
            response = requests.post(f"{self.hive_url}/api/v1/query", 
                                   headers=self.hive_headers, 
                                   json=query)
            response.raise_for_status()
            
            all_cases = response.json()
            eligible_cases = []
            
            for case in all_cases:
                tags = case.get('tags', [])
                if 'analyzed' in tags and 'report' not in tags:
                    eligible_cases.append(case)
            
            return eligible_cases
            
        except requests.exceptions.RequestException as e:
            print(f"ERROR: Error fetching cases: {e}")
            return []

    def add_report_tag_to_case(self, case_id):
        try:
            get_query = {
                "query": [
                    {"_name": "getCase", "idOrName": case_id}
                ]
            }
            
            response = requests.post(f"{self.hive_url}/api/v1/query",
                                   headers=self.hive_headers,
                                   json=get_query)
            response.raise_for_status()
            
            case_data = response.json()
            if not case_data:
                print(f"ERROR: Could not fetch case data for {case_id}")
                return False
            
            case_info = case_data[0] if isinstance(case_data, list) else case_data
            current_tags = case_info.get('tags', [])
            
            if 'report' not in current_tags:
                new_tags = current_tags + ['report']
                
                update_data = {
                    "tags": new_tags
                }
                
                update_response = requests.patch(f"{self.hive_url}/api/v1/case/{case_id}",
                                               headers=self.hive_headers,
                                               json=update_data)
                update_response.raise_for_status()
                
                print(f"SUCCESS: Added 'report' tag to case {case_id}")
                return True
            else:
                print(f"INFO: Case {case_id} already has 'report' tag")
                return True
                
        except requests.exceptions.RequestException as e:
            print(f"ERROR: Failed to add report tag to case {case_id}: {e}")
            return False

    def get_case_observables(self, case_id):
        query = {
            "query": [
                {"_name": "getCase", "idOrName": case_id},
                {"_name": "observables"}
            ]
        }
        
        try:
            response = requests.post(f"{self.hive_url}/api/v1/query",
                                   headers=self.hive_headers,
                                   json=query)
            response.raise_for_status()
            
            observables = response.json()
            return observables
            
        except requests.exceptions.RequestException as e:
            print(f"ERROR: Error fetching observables for case {case_id}: {e}")
            return []

    def get_observable_jobs(self, observable_id):
        query = {
            "query": [
                {"_name": "getObservable", "idOrName": observable_id},
                {"_name": "jobs"}
            ]
        }
        
        try:
            response = requests.post(f"{self.hive_url}/api/v1/query",
                                   headers=self.hive_headers,
                                   json=query)
            response.raise_for_status()
            
            jobs = response.json()
            return jobs
            
        except requests.exceptions.RequestException as e:
            print(f"ERROR: Error fetching jobs for observable {observable_id}: {e}")
            return []

    def extract_summary_from_nested_paths(self, full_report):
        potential_summary_paths = [
            ['summary'],
            ['report', 'summary'],
            ['results', 'summary'],
            ['data', 'summary'],
            ['job', 'summary'],
            ['artifacts', 'summary'],
            ['operations', 'summary']
        ]
        
        for path in potential_summary_paths:
            current_data = full_report
            
            try:
                for key in path:
                    if isinstance(current_data, dict) and key in current_data:
                        current_data = current_data[key]
                    else:
                        break
                else:
                    if current_data and current_data != full_report:
                        return current_data, ' -> '.join(path)
                    
            except (TypeError, AttributeError):
                continue
        
        return {}, 'not_found'

    def get_job_report_and_summary(self, cortex_job_id):
        try:
            response = requests.get(f"{self.cortex_url}/api/job/{cortex_job_id}/report",
                                  headers=self.cortex_headers,
                                  timeout=30)
            
            if response.status_code == 200:
                try:
                    full_report = response.json()
                    summary, summary_path = self.extract_summary_from_nested_paths(full_report)
                    
                    return {
                        'full_report': full_report,
                        'summary': summary,
                        'summary_path': summary_path,
                        'source': 'report_endpoint'
                    }
                except json.JSONDecodeError:
                    pass
            
            alt_response = requests.get(f"{self.cortex_url}/api/job/{cortex_job_id}",
                                      headers=self.cortex_headers,
                                      timeout=30)
            
            if alt_response.status_code == 200:
                try:
                    job_data = alt_response.json()
                    
                    if 'report' in job_data:
                        full_report = job_data['report']
                    else:
                        full_report = job_data
                    
                    summary, summary_path = self.extract_summary_from_nested_paths(full_report)
                    
                    return {
                        'full_report': full_report,
                        'summary': summary,
                        'summary_path': summary_path,
                        'source': 'job_endpoint'
                    }
                except json.JSONDecodeError:
                    pass
            
            return {
                'full_report': {}, 
                'summary': {}, 
                'summary_path': 'failed',
                'source': 'failed'
            }
            
        except requests.exceptions.RequestException as e:
            print(f"ERROR: Network error fetching job report for {cortex_job_id}: {e}")
            return {
                'full_report': {}, 
                'summary': {}, 
                'summary_path': 'network_error',
                'source': 'network_error'
            }

    def create_pdf_report(self, case_data):
        case_number = case_data['case'].get('caseId', 'Unknown')
        case_title = case_data['case'].get('title', 'No Title')
        case_id = case_data['case'].get('_id', 'unknown_id')

        filename = f"case_{case_id}.pdf"
        filepath = os.path.join(self.reports_dir, filename)
        
        doc = SimpleDocTemplate(filepath, pagesize=A4, 
                              rightMargin=72, leftMargin=72, 
                              topMargin=72, bottomMargin=18)
        
        story = []
        styles = getSampleStyleSheet()
        
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=16,
            spaceAfter=30,
            textColor=colors.darkblue
        )
        
        story.append(Paragraph(f"Case Analysis Report - {case_id}", title_style))
        story.append(Paragraph(f"<b>Case Title:</b> {case_title}", styles['Normal']))
        story.append(Paragraph(f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        story.append(Spacer(1, 20))
        
        story.append(Paragraph("Observables & Analyzer Results", styles['Heading2']))
        
        if case_data['observables']:
            for observable in case_data['observables']:
                obs_type = observable.get('dataType', 'Unknown')
                obs_data = observable.get('data', 'No Data')
                obs_id = observable.get('_id', 'Unknown')
                
                story.append(Paragraph(f"<b>Observable:</b> {obs_type} - {obs_data}", styles['Normal']))
                
                jobs = case_data['job_summaries'].get(obs_id, [])
                
                if jobs:
                    job_data = [['Analyzer', 'Status', 'Level', 'Value']]
                    
                    for job in jobs:
                        analyzer_name = job.get('analyzerName', 'Unknown')
                        status = job.get('status', 'Unknown')
                        
                        summary = job.get('summary', {})
                        taxonomies = summary.get('taxonomies', [])
                        
                        if taxonomies:
                            for taxonomy in taxonomies:
                                level = taxonomy.get('level', 'Unknown')
                                value = taxonomy.get('value', 'No Value')
                                job_data.append([analyzer_name, status, level, str(value)])
                        else:
                            job_data.append([analyzer_name, status, 'No Data', 'No Summary'])
                    
                    job_table = Table(job_data, colWidths=[1.5*inch, 0.8*inch, 0.8*inch, 2*inch])
                    job_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 9),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black),
                        ('FONTSIZE', (0, 1), (-1, -1), 8),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ]))
                    story.append(job_table)
                else:
                    story.append(Paragraph("No analyzer results found.", styles['Normal']))
                
                story.append(Spacer(1, 15))
        else:
            story.append(Paragraph("No observables found for this case.", styles['Normal']))
        
        doc.build(story)
        print(f"PDF report created: {filepath}")

    def process_single_case(self, case):
        case_id = case.get('_id')
        case_number = case.get('caseId', 'Unknown')
        case_title = case.get('title', 'No Title')
        
        print(f"Processing Case {case_number}: {case_title}")
        
        case_data = {
            'case': case,
            'observables': self.get_case_observables(case_id),
            'job_summaries': {}
        }
        
        for observable in case_data['observables']:
            obs_id = observable.get('_id')
            jobs = self.get_observable_jobs(obs_id)
            
            job_summaries = []
            for job in jobs:
                cortex_job_id = job.get('cortexJobId')
                
                if cortex_job_id:
                    report_data = self.get_job_report_and_summary(cortex_job_id)
                    job['full_report'] = report_data['full_report']
                    job['summary'] = report_data['summary']
                    job['summary_path'] = report_data['summary_path']
                    job['report_source'] = report_data['source']
                else:
                    job['full_report'] = {}
                    job['summary'] = {}
                    job['summary_path'] = 'no_cortex_id'
                    job['report_source'] = 'no_cortex_id'
                
                job_summaries.append(job)
            
            case_data['job_summaries'][obs_id] = job_summaries
        
        self.create_pdf_report(case_data)
        
        if self.add_report_tag_to_case(case_id):
            print(f"Successfully processed and tagged case {case_number}")
            return True
        else:
            print(f"WARNING: Report created but failed to tag case {case_number}")
            return False

    def run_continuous_monitoring(self, check_interval=300):
        print(f"Starting continuous monitoring (checking every {check_interval} seconds)...")
        print("Press Ctrl+C to stop")
        
        try:
            while True:
                print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Checking for new analyzed cases...")
                
                cases = self.get_analyzed_cases_without_report()
                
                if cases:
                    print(f"Found {len(cases)} new cases to process")
                    
                    for case in cases:
                        try:
                            self.process_single_case(case)
                        except Exception as e:
                            case_id = case.get('caseId', 'Unknown')
                            print(f"ERROR: Failed to process case {case_id}: {e}")
                            continue
                else:
                    print("No new cases found")
                
                print(f"Waiting {check_interval} seconds before next check...")
                time.sleep(check_interval)
                
        except KeyboardInterrupt:
            print("\nMonitoring stopped by user")
        except Exception as e:
            print(f"ERROR: Monitoring stopped due to error: {e}")

# Configuration - Replace with your own values
HIVE_URL = "http://YOUR_THEHIVE_IP:9000"
HIVE_API_KEY = "ENTER_HERE_YOUR_THEHIVE_API_KEY"
CORTEX_URL = "http://YOUR_CORTEX_IP:9001"
CORTEX_API_KEY = "ENTER_HERE_YOUR_CORTEX_API_KEY"

# Check interval in seconds (default: 5 minutes)
CHECK_INTERVAL = 300

if __name__ == "__main__":
    print("Initializing TheHive Case Analyzer...")
    analyzer = TheHiveCaseAnalyzer(HIVE_URL, HIVE_API_KEY, CORTEX_URL, CORTEX_API_KEY)
    analyzer.run_continuous_monitoring(CHECK_INTERVAL)
