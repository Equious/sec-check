# main.py
import shutil
import argparse
import logging
from pathlib import Path
import json
import re # For robust JSON cleaning

from config import WORKSPACE_DIR # Assuming this is used somewhere or for future
from utils import (
    setup_logging,
    read_file_content,
    construct_file_function_list_string # For Option 1 localization
)
from llm_handler import LLMHandler
from repo_analyzer import RepoAnalyzer # This should now have AST parsing capabilities
from vulnerability_manager import VulnerabilityManager
from poc_generator import PoCGenerator # Assuming Foundry-focused or adaptable
from reporting import ReportGenerator
from static_analyzer import StaticAnalyzer

# Setup basic logging
setup_logging(level=logging.INFO) # Set to DEBUG for more verbose output
logger = logging.getLogger(__name__)

# Constants
MAX_UNIQUE_FILES_PER_VULN_FOR_DETECTION = 20 # Limit how many unique files we'll run full detection on for a single vuln type
MAX_LOCALIZATION_FILES_TO_LIST_IN_PROMPT = 15
MAX_LOCALIZATION_FUNCTIONS_PER_FILE = 20
MAX_FUNC_LIST_STR_LEN = 15000 # Max length for the function list part of the prompt

def clean_llm_json_response(raw_response_str: str) -> str:
    """
    Cleans a raw string response from an LLM, attempting to extract a valid JSON object.
    Handles markdown code fences and tries to find the first complete JSON object.
    """
    if not raw_response_str or not raw_response_str.strip():
        logger.warning("Received an empty raw string for JSON cleaning.")
        return "" # Return empty string if input is None or whitespace only

    text_to_parse = raw_response_str.strip()

    # Common patterns of markdown fences
    prefixes_to_remove = ["```json", "```"]
    suffix_to_remove = "```"

    for prefix in prefixes_to_remove:
        if text_to_parse.startswith(prefix):
            text_to_parse = text_to_parse[len(prefix):].strip()
            break # Remove only one type of prefix

    if text_to_parse.endswith(suffix_to_remove):
        text_to_parse = text_to_parse[:-len(suffix_to_remove)].strip()
    
    # Fallback: If it still doesn't look like JSON, try to extract the first valid JSON object or array
    if not (text_to_parse.startswith('{') and text_to_parse.endswith('}')) and \
       not (text_to_parse.startswith('[') and text_to_parse.endswith(']')):
        logger.debug(f"String after initial fence stripping ('{text_to_parse[:100]}...') does not clearly start/end with JSON object/array markers. Attempting regex extraction.")
        match = re.search(r'(\{.*\}|\[.*\])', text_to_parse, re.DOTALL)
        if match:
            extracted_json_str = match.group(0)
            logger.debug(f"Regex extracted potential JSON: '{extracted_json_str[:200]}...'")
            try:
                json.loads(extracted_json_str) # Test parse
                text_to_parse = extracted_json_str 
                logger.info("Successfully extracted a valid JSON block using regex fallback.")
            except json.JSONDecodeError:
                logger.warning(f"Regex extracted a block, but it's not valid JSON. Using string after initial stripping: '{text_to_parse[:100]}...'")
        else:
            logger.warning(f"Could not find a JSON-like block using regex. Using string after initial stripping: '{text_to_parse[:100]}...'")
    
    return text_to_parse


def main():
    parser = argparse.ArgumentParser(description="AI Smart Contract Auditor")
    parser.add_argument("repo_url", help="GitHub repository URL of the smart contract project.")
    parser.add_argument(
        "--framework",
        choices=["hardhat", "foundry"],
        default="foundry", 
        help="Specify the project framework (foundry is primary for PoC generation)."
    )
    parser.add_argument(
        "--use-slither",
        action="store_true",
        help="Enable the use of Slither for static analysis (recommended)."
    )
    parser.add_argument(
        "--skip-poc",
        action="store_true",
        help="Skip the Proof of Concept generation and execution phase."
    )
    parser.add_argument(
        "--max-output-tokens-llm",
        type=int,
        default=16384, # Increased default, good for detailed explanations
        help="Max output tokens for LLM calls expecting substantial text/JSON."
    )

    args = parser.parse_args()

    logger.info(f"Starting AI Smart Contract Audit for: {args.repo_url}")
    logger.info(f"Project framework selected: {args.framework.capitalize()}")
    if args.use_slither:
        logger.info("Slither static analysis is ENABLED.")
    if args.skip_poc:
        logger.info("Proof of Concept generation is SKIPPED.")
    logger.info(f"LLM max output tokens for calls set to: {args.max_output_tokens_llm}")

    try:
        llm = LLMHandler()
    except Exception as e:
        logger.error(f"Fatal: Could not initialize LLM Handler: {e}", exc_info=True)
        return

    repo_analyzer = RepoAnalyzer(args.repo_url, llm)
    vuln_manager = VulnerabilityManager(llm)
    report_generator = ReportGenerator(project_name=repo_analyzer.repo_name)

    logger.info("--- Step 1: Analyzing Repository (includes AST parsing for functions) ---")
    if not repo_analyzer.analyze():
        logger.error("Failed to analyze repository. Exiting.")
        return
    
    logger.info(f"Project local path: {repo_analyzer.local_repo_path}")
    logger.info(f"Project summary: {repo_analyzer.project_summary}")
    logger.info(f"Found {len(repo_analyzer.solidity_files)} core Solidity files.")
    logger.info(f"Detected standards/patterns: {repo_analyzer.detected_standards}")
    if repo_analyzer.file_function_definitions:
        for rel_path, funcs in list(repo_analyzer.file_function_definitions.items())[:2]:
            func_names = [f.get('name', 'N/A') for f in funcs[:5]]
            logger.debug(f"Functions in {rel_path} (first 5 or fewer): {func_names}")
    else:
        logger.warning("No function definitions were extracted by RepoAnalyzer.")


    logger.info("--- Step 2: Determining Applicable Vulnerabilities ---")
    applicable_vulnerabilities = vuln_manager.get_applicable_vulnerabilities(
        project_summary=repo_analyzer.project_summary,
        contract_contents=repo_analyzer.contract_contents,
        detected_standards=repo_analyzer.detected_standards
    )
    if not applicable_vulnerabilities:
        logger.warning("No applicable vulnerabilities determined by LLM after pre-filtering. This might be an LLM or checklist issue.")
        report_generator.generate_report(repo_analyzer.project_summary)
        return
    logger.info(f"LLM identified {len(applicable_vulnerabilities)} potentially applicable vulnerabilities for deep check.")
    for v_idx, v_detail in enumerate(applicable_vulnerabilities):
        logger.debug(f"  Applicable Vuln {v_idx+1}: ID={v_detail['id']}, Name='{v_detail['name']}', Reasoning='{v_detail.get('llm_applicability_reasoning', 'N/A')}'")

    slither_project_results = None
    if args.use_slither:
        logger.info("--- Initializing Slither Static Analyzer ---")
        slither_analyzer = StaticAnalyzer(project_path=repo_analyzer.local_repo_path)
        slither_project_results = slither_analyzer.analyze_project_with_slither()
        if slither_project_results and "detectors" in slither_project_results:
            logger.info(f"Slither found {len(slither_project_results.get('detectors',[]))} potential issue types project-wide.")
        else:
            logger.warning("Slither project analysis did not return results or failed.")

    poc_generator = None
    if not args.skip_poc:
        if args.framework.lower() == "foundry":
            poc_generator = PoCGenerator(llm, repo_analyzer.local_repo_path)
            logger.info("Foundry PoC Generator initialized.")
        else:
            logger.warning(f"PoC generation for framework '{args.framework}' is not optimally supported. Skipping PoC generation for non-Foundry projects.")
            args.skip_poc = True

    logger.info("--- Steps 3 & 4: Localizing and Checking Vulnerabilities ---")
    verified_findings_count = 0

    for vuln_details in applicable_vulnerabilities:
        logger.info(f"\nInvestigating Vulnerability: {vuln_details['name']} (ID: {vuln_details['id']})")
        
        # --- Step 3: Localization - Identify relevant files ---
        # For this strategy, localization primarily identifies relevant files.
        # The subsequent detection step will analyze the full file for all instances.
        
        file_function_info_str = construct_file_function_list_string(
            repo_analyzer.file_function_definitions,
            max_files_to_list=MAX_LOCALIZATION_FILES_TO_LIST_IN_PROMPT,
            max_functions_per_file=MAX_LOCALIZATION_FUNCTIONS_PER_FILE
        )
        if len(file_function_info_str) > MAX_FUNC_LIST_STR_LEN:
            logger.warning(f"Function list string for localization is very long ({len(file_function_info_str)} chars). Truncating.")
            file_function_info_str = file_function_info_str[:MAX_FUNC_LIST_STR_LEN] + "\n... (function list truncated)"

        checklist_typical_funcs_str = "N/A"
        if 'applicability_conditions' in vuln_details and 'typical_functions_involved' in vuln_details['applicability_conditions']:
            checklist_typical_funcs_str = ', '.join(vuln_details['applicability_conditions']['typical_functions_involved'])
            if not checklist_typical_funcs_str: checklist_typical_funcs_str = "None specified."

        # This prompt asks for relevant files, but the detection prompt will do the heavy lifting for instances.
        # We can still ask for function hints here to potentially guide Slither merging or initial focus.
        localization_prompt = f"""
        You are an AI Smart Contract Auditor.
        Project Summary: {repo_analyzer.project_summary}

        We are looking for the vulnerability: "{vuln_details['name']}" (ID: {vuln_details['id']})
        Description: "{vuln_details['description']}"
        Keywords associated: {', '.join(vuln_details.get('keywords', []))}
        General typical functions for this vuln type (guidance only): {checklist_typical_funcs_str}

        The project has the following Solidity files and their extracted function/modifier definitions:
        --- FILE & FUNCTION LISTINGS START ---
        {file_function_info_str}
        --- FILE & FUNCTION LISTINGS END ---

        Based on ALL the information, which specific `file_path`s from the listings are MOST LIKELY
        to contain instances of THIS vulnerability? You can also suggest a `function_name` if a specific one stands out,
        but the primary goal is to identify relevant files. If multiple functions in a file might be relevant,
        or if it's a file-level concern, providing just the `file_path` (and "N/A" for function_name) is fine.
        
        Limit your suggestions to a few most relevant `file_path`s.
        
        Respond ONLY with a valid JSON object. Do NOT include markdown.
        The JSON should have a key "relevant_locations", which is a list of objects.
        Each object must have "file_path" (string) and optionally "function_name" (string, or "N/A").
        Example:
        {{
          "relevant_locations": [
            {{ "file_path": "contracts/core/Vault.sol", "function_name": "withdraw" }}, 
            {{ "file_path": "contracts/Main.sol", "function_name": "N/A" }}
          ]
        }}
        """
        logger.info(f"Requesting LLM file-level localization for '{vuln_details['name']}'. Prompt length approx {len(localization_prompt)}. Max output tokens: {args.max_output_tokens_llm}")
        localization_response_raw_str = llm.generate_text(
            localization_prompt,
            temperature=0.15,
            max_output_tokens=args.max_output_tokens_llm # Using general max tokens, adjust if this returns small JSON
        )
        logger.debug(f"Raw LLM localization response: {localization_response_raw_str}")

        initial_relevant_locations = []
        if localization_response_raw_str and localization_response_raw_str.strip():
            cleaned_loc_response = clean_llm_json_response(localization_response_raw_str)
            logger.debug(f"Cleaned LLM localization response: {cleaned_loc_response[:500]}...")
            try:
                parsed_loc_response = json.loads(cleaned_loc_response)
                initial_relevant_locations = parsed_loc_response.get("relevant_locations", [])
                if not isinstance(initial_relevant_locations, list) or \
                   not all(isinstance(loc, dict) and 'file_path' in loc for loc in initial_relevant_locations if isinstance(loc, dict)):
                    logger.warning(f"LLM localization: 'relevant_locations' bad format. Response: {cleaned_loc_response}")
                    initial_relevant_locations = []
            except json.JSONDecodeError as e_json_loc:
                logger.error(f"Could not parse LLM localization response for '{vuln_details['name']}': {cleaned_loc_response}", exc_info=True)
        else:
            logger.warning(f"LLM returned empty response for localization of '{vuln_details['name']}'.")
        
        # Consolidate relevant files from LLM and Slither
        all_candidate_files = {} # Use dict to store file_path -> set of suggested functions (or "N/A")
        for loc in initial_relevant_locations:
            fp = loc.get('file_path')
            fn = loc.get('function_name', "N/A")
            if fp:
                if fp not in all_candidate_files: all_candidate_files[fp] = set()
                all_candidate_files[fp].add(fn)

        if args.use_slither and slither_project_results and 'detectors' in slither_project_results:
            # (Simplified Slither integration for file-level for now)
            # A more advanced integration would map Slither detectors to vuln_details more precisely
            sl_vuln_id = vuln_details.get('swc_id')
            sl_keywords = [k.lower() for k in vuln_details.get('keywords', [])]
            sl_name_approx = vuln_details['name'].lower()

            for sl_finding in slither_project_results['detectors']:
                sl_check = sl_finding.get('check', '').lower()
                is_sl_match = (sl_vuln_id and sl_vuln_id in sl_finding.get('id','')) or \
                              any(kw in sl_check for kw in sl_keywords if kw) or \
                              any(kw in sl_name_approx for kw in sl_keywords if kw and len(kw)>3)


                if is_sl_match:
                    for element in sl_finding.get('elements', []):
                        sl_fp = element.get('source_mapping', {}).get('filename_relative')
                        if sl_fp:
                            if sl_fp not in all_candidate_files: all_candidate_files[sl_fp] = set()
                            # Slither might point to a function, add it as a hint, but detection will scan whole file
                            sl_fn_hint = element.get('name') if element.get('type') == 'function' else "N/A"
                            all_candidate_files[sl_fp].add(sl_fn_hint) 
                            logger.info(f"Slither identified file '{sl_fp}' (func hint: {sl_fn_hint}) as potentially relevant for '{vuln_details['name']}'.")
        
        unique_files_to_check_for_this_vuln = sorted(list(all_candidate_files.keys()))
        
        if not unique_files_to_check_for_this_vuln:
            logger.warning(f"No relevant files identified for '{vuln_details['name']}' after LLM and Slither. Defaulting to first few project files.")
            unique_files_to_check_for_this_vuln = [str(p.relative_to(repo_analyzer.local_repo_path)) for p in repo_analyzer.solidity_files[:MAX_UNIQUE_FILES_PER_VULN_FOR_DETECTION]]

        logger.info(f"Total unique files to perform full detection for '{vuln_details['name']}': {len(unique_files_to_check_for_this_vuln)}. Will check up to {MAX_UNIQUE_FILES_PER_VULN_FOR_DETECTION}.")

        # --- Step 4: Detection - One pass per (Vulnerability ID, File Path) ---
        for file_idx, relative_file_path_str in enumerate(unique_files_to_check_for_this_vuln):
            if file_idx >= MAX_UNIQUE_FILES_PER_VULN_FOR_DETECTION:
                logger.info(f"Reached max files ({MAX_UNIQUE_FILES_PER_VULN_FOR_DETECTION}) for detailed detection of '{vuln_details['name']}'. Skipping remaining files for this vulnerability type.")
                break
            
            logger.info(f"Performing full detection for '{vuln_details['name']}' in file: {relative_file_path_str}")
            
            absolute_file_path = repo_analyzer.local_repo_path / relative_file_path_str
            if not absolute_file_path.exists(): # Should be caught by earlier checks, but good to have
                logger.warning(f"File {relative_file_path_str} for detection not found. Skipping.")
                continue

            contract_code_content = read_file_content(absolute_file_path)
            if not contract_code_content:
                logger.warning(f"Could not read content of {relative_file_path_str} for detection. Skipping.")
                continue
            
            detection_prompt = f"""
            You are an AI Smart Contract Security Auditor. Your analysis must be based *solely* on the provided contract code and the specified vulnerability.
            Avoid speculation about external conditions or features not present in the code. Be definitive in your findings.

            Analyze the ENTIRE smart contract code from file '{relative_file_path_str}'
            for the specific vulnerability: "{vuln_details['name']}" (ID: {vuln_details['id']}).
            Vulnerability Description: {vuln_details['description']}

            Full Contract Code for '{relative_file_path_str}':
            ```solidity
            {contract_code_content} 
            ```

            Assessment Task:
            1. Determine if the contract *as written* exhibits the "{vuln_details['name']}" vulnerability.
            2. If vulnerable:
               - Provide a general explanation rooted *only* in the provided code, detailing how the vulnerability applies.
               - List ALL functions/modifiers and their corresponding line numbers (or code context) where this vulnerability manifests. Be specific to the code.
            3. If NOT vulnerable:
               - Provide a clear explanation of why the vulnerability does not apply to this code or is mitigated by mechanisms *present in this code*.

            **Instructions for your response:**
            - Base your entire assessment on the provided code ONLY.
            - Do NOT speculate about "if the vault had other mechanics" or "if external contracts are malicious" unless such interactions are explicitly defined or initiated within this code.
            - If a standard pattern (e.g., ERC721 approval) has inherent risks, describe them but clearly state if the *provided contract code itself* either creates, exacerbates, or fails to mitigate that risk in its specific implementation.
            - Be factual and avoid conditional language like "could happen" or "might be possible" unless you are describing a direct consequence of the code's logic. If the code *allows* something, state that.

            Respond ONLY with a valid JSON object. Do NOT include markdown.
            The JSON object must have the following keys:
            - "is_vulnerable" (boolean)
            - "general_explanation" (string: overall explanation for this file, based *only* on the code)
            - "instances" (list of objects, or empty list if not vulnerable. Each object should have "function_name": string (or "Contract-Level" / "N/A"), "lines": string, and optionally "specific_explanation": string, detailing the issue in that specific instance)
            - "confidence_score" (float: 0.0 to 1.0, your confidence in the overall assessment for this file)
            
            Example if vulnerable:
            {{
              "is_vulnerable": true,
              "general_explanation": "The contract's `processOrder` function calls an external contract before updating internal state, directly enabling a reentrancy attack based on its current implementation.",
              "instances": [
                {{"function_name": "processOrder", "lines": "78-83", "specific_explanation": "The call to `paymentProcessor.executePayment()` on line 80 occurs before `order.status` is updated on line 82."}}
              ],
              "confidence_score": 0.95
            }}
            Example if not vulnerable:
            {{
              "is_vulnerable": false,
              "general_explanation": "The contract consistently applies the checks-effects-interactions pattern in all functions involving external calls. For example, in `withdrawFunds`, balance updates (lines 50-51) precede the external call (line 53).",
              "instances": [],
              "confidence_score": 0.98
            }}
            """
            logger.info(f"Requesting LLM detection for '{vuln_details['name']}' in {relative_file_path_str}. Prompt length approx {len(detection_prompt)}. Max output tokens: {args.max_output_tokens_llm}")
            detection_response_raw_str = llm.generate_text(
                detection_prompt,
                temperature=0.1, 
                max_output_tokens=args.max_output_tokens_llm
            )
            logger.debug(f"Raw LLM detection response for {relative_file_path_str}: {detection_response_raw_str}")

            if not detection_response_raw_str or not detection_response_raw_str.strip():
                logger.error(f"LLM returned empty response for detection in {relative_file_path_str} for vuln '{vuln_details['name']}'. Skipping this file for this vuln.")
                continue

            cleaned_detect_response = clean_llm_json_response(detection_response_raw_str)
            logger.debug(f"Cleaned LLM detection response for JSON parsing: {cleaned_detect_response[:500]}...")

            try:
                detection_result = json.loads(cleaned_detect_response)
                is_vulnerable = detection_result.get("is_vulnerable", False)
                general_explanation = detection_result.get("general_explanation", "No general explanation provided by LLM.")
                instances = detection_result.get("instances", [])
                confidence = detection_result.get("confidence_score", 0.0)

                if isinstance(confidence, str):
                    try: confidence = float(confidence)
                    except ValueError: confidence = 0.0; logger.warning("Confidence score parse error.")
                
                logger.info(f"LLM Detection for '{vuln_details['name']}' in {relative_file_path_str}: "
                            f"Is Vulnerable? {is_vulnerable}, Confidence: {confidence:.2f}, Found {len(instances)} instances.")

                if is_vulnerable and confidence >= 0.7: # Overall confidence for this file
                    if not instances: # Vulnerable but no specific instances given by LLM
                        logger.warning(f"LLM marked as vulnerable but gave no instances for '{vuln_details['name']}' in {relative_file_path_str}. Using general explanation.")
                        # Create a placeholder instance for reporting
                        instances = [{"function_name": "Overall Contract", "lines": "N/A", "specific_explanation": "LLM indicated vulnerability but did not pinpoint specific instances."}]
                    
                    consolidated_func_names = []
                    consolidated_lines_details = []
                    report_explanation_parts = [general_explanation]

                    for inst_idx, inst in enumerate(instances):
                        func = inst.get("function_name", "N/A")
                        lns = inst.get("lines", "N/A")
                        spec_exp = inst.get("specific_explanation")
                        
                        consolidated_func_names.append(func)
                        consolidated_lines_details.append(f"{func} (Lines: {lns})")
                        if spec_exp:
                            report_explanation_parts.append(f"  - Instance in '{func}' (Lines: {lns}): {spec_exp}")
                    
                    final_report_explanation = "\n".join(report_explanation_parts)
                    final_report_functions = ", ".join(sorted(list(set(filter(None, consolidated_func_names))))) or "N/A"
                    final_report_lines = "; ".join(consolidated_lines_details) or "N/A"

                    logger.info(f"High confidence finding: '{vuln_details['name']}' in {relative_file_path_str}. Instances found: {len(instances)}")
                    
                    poc_status, poc_code, poc_log = "NOT_ATTEMPTED", None, None
                    poc_target_function = instances[0].get("function_name") if instances and instances[0].get("function_name") not in ["N/A", "Contract-Level"] else None
                    
                    if not args.skip_poc and poc_generator:
                        poc_status, poc_code, poc_log = poc_generator.attempt_poc_generation_and_execution(
                            vulnerability_details=vuln_details,
                            vulnerable_code_snippet=contract_code_content,
                            full_contract_code=contract_code_content,
                            contract_name=Path(relative_file_path_str).stem,
                            contract_relative_path=relative_file_path_str,
                            function_name=poc_target_function
                        )
                    
                    if poc_status == "SUCCESS" or (args.skip_poc and confidence >= 0.75):
                        report_generator.add_finding(
                            vulnerability_details=vuln_details,
                            contract_file=relative_file_path_str,
                            function_name=final_report_functions,
                            line_numbers=final_report_lines,
                            code_snippet=contract_code_content, # Can be refined if needed
                            llm_explanation=final_report_explanation,
                            poc_status=poc_status,
                            poc_code=poc_code,
                            poc_log=poc_log
                        )
                        verified_findings_count += 1
                    elif poc_status != "NOT_ATTEMPTED":
                        report_generator.add_finding(
                            vulnerability_details=vuln_details,
                            contract_file=relative_file_path_str,
                            function_name=final_report_functions,
                            line_numbers=final_report_lines,
                            code_snippet=contract_code_content,
                            llm_explanation=final_report_explanation + f"\n\nNOTE: LLM deemed this vulnerable ({confidence*100:.0f}% conf), but automated PoC status was: {poc_status.upper()}.",
                            poc_status=poc_status,
                            poc_code=poc_code,
                            poc_log=poc_log
                        )
            except json.JSONDecodeError as e_json_detect:
                logger.error(f"Could not parse LLM detection response for '{vuln_details['name']}' in {relative_file_path_str}: {cleaned_detect_response}", exc_info=True)
            except Exception as e_process_detect:
                logger.error(f"Error processing detection result for {relative_file_path_str} and vuln '{vuln_details['name']}': {e_process_detect}", exc_info=True)

    logger.info(f"\n--- Step 6: Generating Audit Report ({verified_findings_count} verified findings) ---")
    try:
        report_path = report_generator.generate_report(project_summary=repo_analyzer.project_summary)
        logger.info(f"Audit complete. Report generated at: {report_path.resolve()}")
    except Exception as e:
        logger.error(f"Failed to generate final report: {e}", exc_info=True)

    # Optional: Cleanup workspace
    # try:
    #     if repo_analyzer.local_repo_path.exists():
    #         shutil.rmtree(repo_analyzer.local_repo_path)
    #         logger.info(f"Cleaned up workspace: {repo_analyzer.local_repo_path}")
    # except Exception as e_cleanup:
    #     logger.error(f"Error cleaning up workspace: {e_cleanup}")

if __name__ == "__main__":
    main()