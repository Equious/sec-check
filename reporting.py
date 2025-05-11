# reporting.py
import logging
from typing import List, Dict, Any
from pathlib import Path
from collections import defaultdict # For grouping

logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self, project_name: str, report_dir: Path = Path("reports"), framework_hint: str = "foundry"): # Added framework_hint
        self.project_name = project_name
        self.report_dir = report_dir
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.findings: List[Dict[str, Any]] = []
        self.framework_hint = framework_hint.lower() # For PoC code block language hint

    def add_finding(
        self,
        vulnerability_details: Dict[str, Any],
        contract_file: str,
        function_name: str = "N/A", # This will be a consolidated string of function names
        line_numbers: str = "N/A", # This will be a consolidated string of "func (lines); func (lines)"
        code_snippet: str = "N/A", # This will be the full contract code
        llm_explanation: str = "N/A", # This will be the consolidated explanation
        poc_status: str = "NOT_ATTEMPTED",
        poc_code: str = None,
        poc_log: str = None
    ):
        # Ensure severity is a string for consistent sorting and display
        raw_severity = vulnerability_details.get("severity")
        if raw_severity is None:
            final_severity = "Severity Not Specified" # Clearer than "None" or N/A
        elif isinstance(raw_severity, str) and raw_severity.strip() == "":
            final_severity = "Severity Not Specified"
        else:
            final_severity = str(raw_severity)


        finding = {
            "vulnerability_id": vulnerability_details.get("id"),
            "vulnerability_name": vulnerability_details.get("name", "Unknown Vulnerability"), # 'name' from flattened checklist
            "severity": final_severity,
            "description": vulnerability_details.get("description", "No description provided in checklist."), # 'description' from checklist
            "categories": " -> ".join(vulnerability_details.get("inherited_categories", [])),
            "contract_file": contract_file,
            "function_name_consolidated": function_name, # Store consolidated function names
            "line_numbers_consolidated": line_numbers,   # Store consolidated line details
            "full_contract_code": code_snippet, # Store the full contract code
            "ai_assessment_consolidated": llm_explanation, # Store consolidated AI assessment
            "poc_status": poc_status,
            "poc_code": poc_code,
            "poc_log": poc_log,
            "cwe": vulnerability_details.get("cwe", "N/A"),
            "swc_id": vulnerability_details.get("swc_id", "N/A"),
            "recommendation": vulnerability_details.get("remediation", "Consult detailed documentation for this vulnerability type."),
            "references": vulnerability_details.get("references", [])
        }
        self.findings.append(finding)
        logger.info(f"Added finding: {finding['vulnerability_name']} in {contract_file}")

    def generate_report(self, project_summary: str) -> Path:
        # Report filename now more generic as it covers all contracts
        report_filename = f"{self.project_name.replace('/', '_')}_full_audit_report.md"
        report_path = self.report_dir / report_filename
        
        report_content = f"# AI Smart Contract Audit Report for: {self.project_name}\n\n"
        report_content += f"## Project Summary\n{project_summary}\n\n"
        
        if not self.findings:
            report_content += "## Audit Findings\nNo vulnerabilities verified with high confidence in this run.\n"
        else:
            # Group findings by contract_file
            findings_by_contract: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
            for f_item in self.findings:
                findings_by_contract[f_item['contract_file']].append(f_item)

            report_content += f"## Audit Findings Summary\n"
            report_content += f"- Total Verified High-Confidence Vulnerabilities: {len(self.findings)}\n"
            report_content += f"- Contracts Analyzed with Findings: {len(findings_by_contract)}\n\n"
            report_content += "---\n\n"


            # Sort contracts by path for consistent ordering
            sorted_contract_paths = sorted(findings_by_contract.keys())

            for contract_path in sorted_contract_paths:
                contract_findings = findings_by_contract[contract_path]
                report_content += f"# Contract: `{contract_path}`\n\n"
                
                # Sort findings within this contract by severity (example values, adjust as needed)
                severity_order = {
                    "Critical": 0, "High": 1, "Medium": 2, "Low": 3, 
                    "Informational": 4, "Severity Not Specified": 5, "N/A": 5
                } # Added "N/A"
                sorted_contract_findings = sorted(
                    contract_findings, 
                    key=lambda x: (severity_order.get(x.get("severity"), 99), x.get("vulnerability_name", ""))
                )

                for i, finding in enumerate(sorted_contract_findings):
                    # Use a more descriptive heading for each finding
                    report_content += f"## {i+1}. {finding['vulnerability_name']} ({finding['severity']})\n\n"
                    report_content += f"- **Vulnerability ID:** `{finding['vulnerability_id']}`\n"
                    if finding.get('categories'):
                        report_content += f"- **Checklist Category:** {finding['categories']}\n"
                    
                    # These are now consolidated strings from the detection phase
                    report_content += f"- **Relevant Functions/Areas:** {finding.get('function_name_consolidated', 'N/A')}\n"
                    report_content += f"- **Specific Lines/Context:** {finding.get('line_numbers_consolidated', 'N/A')}\n"
                    
                    report_content += f"\n### Checklist Description:\n> {finding['description']}\n" # Quoted for emphasis
                    
                    if finding.get('cwe') and finding['cwe'] != "N/A": 
                        report_content += f"- **CWE:** {finding['cwe']}\n"
                    if finding.get('swc_id') and finding['swc_id'] != "N/A": 
                        report_content += f"- **SWC ID:** {finding['swc_id']}\n"
                    
                    report_content += f"\n### AI Assessment & Instances:\n{finding['ai_assessment_consolidated']}\n" # This now contains general + instance details
                    
                    # Option to include full contract code once per contract, or not at all if too verbose
                    # For now, let's not repeat it for every finding if it's the same contract.
                    # The "Vulnerable Code Snippet" was the full contract.
                    # We can put it at the beginning of the contract's section.
                    # Or, a PoC might be more illustrative.

                    report_content += f"\n### Proof of Concept (PoC) Status: **{finding['poc_status']}**\n"
                    if finding['poc_code']:
                        # Determine PoC language based on framework hint or content
                        poc_lang = "javascript" if self.framework_hint == "hardhat" else "solidity"
                        if ".js" in finding['poc_code'][:150].lower() or "ethers" in finding['poc_code'].lower():
                            poc_lang = "javascript"
                        elif "contract " in finding['poc_code'][:150].lower() and "Test is Test" in finding['poc_code']:
                            poc_lang = "solidity"
                            
                        report_content += f"\n#### PoC Code:\n```{poc_lang}\n{finding['poc_code']}\n```\n"
                    
                    if finding['poc_log']:
                        log_snippet = finding['poc_log']
                        max_log_len = 1500
                        if len(log_snippet) > max_log_len:
                            log_snippet = log_snippet[:max_log_len//2] + "\n...\n[Log Truncated]\n...\n" + log_snippet[-max_log_len//2:]
                        report_content += f"\n#### PoC Execution Log (Snippet):\n```text\n{log_snippet}\n```\n"
                    
                    report_content += f"\n### Recommendation (from checklist):\n{finding.get('recommendation', 'N/A')}\n"
                    if finding.get('references'):
                        report_content += f"\n### References (from checklist):\n"
                        for ref in finding['references']:
                            report_content += f"- {ref}\n"
                    report_content += "\n---\n\n" # Separator between findings within a contract
                
                report_content += "\n---\n\n" # Separator between contracts
        
        # Add vulnerable code snippet at the end of the report or per contract (once)
        # For simplicity, let's try adding referenced code once per contract if findings exist for it
        # This part needs to be integrated carefully if we want to show code snippets.
        # The current `add_finding` takes `code_snippet` as the full contract code.
        # We can display it once per contract section.

        # Rebuild report_content to insert contract code at the start of each contract's section
        final_report_content = f"# AI Smart Contract Audit Report for: {self.project_name}\n\n"
        final_report_content += f"## Project Summary\n{project_summary}\n\n"

        if not self.findings:
            final_report_content += "## Audit Findings\nNo vulnerabilities verified with high confidence in this run.\n"
        else:
            findings_by_contract_for_display: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
            for f_item in self.findings:
                findings_by_contract_for_display[f_item['contract_file']].append(f_item)

            final_report_content += f"## Audit Findings Summary\n"
            final_report_content += f"- Total Verified High-Confidence Vulnerabilities: {len(self.findings)}\n"
            final_report_content += f"- Contracts Analyzed with Findings: {len(findings_by_contract_for_display)}\n\n"
            final_report_content += "---\n\n"

            sorted_contract_paths_for_display = sorted(findings_by_contract_for_display.keys())

            for contract_path in sorted_contract_paths_for_display:
                contract_findings_list = findings_by_contract_for_display[contract_path]
                final_report_content += f"# Contract: `{contract_path}`\n\n"

                # Add the contract code once at the beginning of its section
                if contract_findings_list: # Should always be true if in this loop
                    full_code = contract_findings_list[0].get("full_contract_code")
                    if full_code:
                        final_report_content += f"## Full Contract Code (`{contract_path}`):\n"
                        final_report_content += f"```solidity\n{full_code}\n```\n\n"
                
                severity_order = {
                    "Critical": 0, "High": 1, "Medium": 2, "Low": 3, 
                    "Informational": 4, "Severity Not Specified": 5, "N/A": 5
                }
                sorted_contract_findings_list = sorted(
                    contract_findings_list, 
                    key=lambda x: (severity_order.get(x.get("severity"), 99), x.get("vulnerability_name", ""))
                )

                for i, finding_item in enumerate(sorted_contract_findings_list):
                    final_report_content += f"## {i+1}. {finding_item['vulnerability_name']} ({finding_item['severity']})\n\n"
                    final_report_content += f"- **Vulnerability ID:** `{finding_item['vulnerability_id']}`\n"
                    if finding_item.get('categories'):
                        final_report_content += f"- **Checklist Category:** {finding_item['categories']}\n"
                    final_report_content += f"- **Relevant Functions/Areas:** {finding_item.get('function_name_consolidated', 'N/A')}\n"
                    final_report_content += f"- **Specific Lines/Context:** {finding_item.get('line_numbers_consolidated', 'N/A')}\n"
                    final_report_content += f"\n### Checklist Description:\n> {finding_item['description']}\n"
                    if finding_item.get('cwe') and finding_item['cwe'] != "N/A": final_report_content += f"- **CWE:** {finding_item['cwe']}\n"
                    if finding_item.get('swc_id') and finding_item['swc_id'] != "N/A": final_report_content += f"- **SWC ID:** {finding_item['swc_id']}\n"
                    final_report_content += f"\n### AI Assessment & Instances:\n{finding_item['ai_assessment_consolidated']}\n"
                    final_report_content += f"\n### Proof of Concept (PoC) Status: **{finding_item['poc_status']}**\n"
                    if finding_item['poc_code']:
                        poc_lang = "javascript" if self.framework_hint == "hardhat" else "solidity"
                        if ".js" in finding_item['poc_code'][:150].lower() or "ethers" in finding_item['poc_code'].lower(): poc_lang = "javascript"
                        elif "contract " in finding_item['poc_code'][:150].lower() and "Test is Test" in finding_item['poc_code']: poc_lang = "solidity"
                        final_report_content += f"\n#### PoC Code:\n```{poc_lang}\n{finding_item['poc_code']}\n```\n"
                    if finding_item['poc_log']:
                        log_snippet = finding_item['poc_log']
                        max_log_len = 1500
                        if len(log_snippet) > max_log_len: log_snippet = log_snippet[:max_log_len//2] + "\n...\n[Log Truncated]\n...\n" + log_snippet[-max_log_len//2:]
                        final_report_content += f"\n#### PoC Execution Log (Snippet):\n```text\n{log_snippet}\n```\n"
                    final_report_content += f"\n### Recommendation (from checklist):\n{finding_item.get('recommendation', 'N/A')}\n"
                    if finding_item.get('references'):
                        final_report_content += f"\n### References (from checklist):\n"
                        for ref in finding_item['references']: final_report_content += f"- {ref}\n"
                    final_report_content += "\n---\n\n"
                final_report_content += "\n---\n\n"


        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(final_report_content) # Use the rebuilt content
            logger.info(f"Report generated: {report_path}")
            return report_path
        except Exception as e:
            logger.error(f"Failed to write report: {e}", exc_info=True)
            raise