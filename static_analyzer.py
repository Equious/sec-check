# static_analyzer.py
import subprocess
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

# Ensure 'slither' command is available in the PATH or provide full path.
SLITHER_COMMAND = "slither" # or "/path/to/your/slither"

class StaticAnalyzer:
    def __init__(self, project_path: Path):
        self.project_path = project_path

    def run_slither_on_file(self, sol_file_path: Path) -> Optional[List[Dict[str, Any]]]:
        """
        Runs Slither on a specific Solidity file and returns parsed JSON output.
        """
        if not sol_file_path.exists():
            logger.error(f"Slither analysis: Solidity file not found {sol_file_path}")
            return None

        # Slither works best on a project context, but can analyze individual files.
        # For project context, you'd run on self.project_path
        # For a single file, it might miss project-wide context.
        # Consider running slither on the entire self.project_path and then filtering results.
        
        # This example targets a single file for simplicity in calling.
        # However, Slither's strength is project-wide analysis.
        # command = [SLITHER_COMMAND, str(sol_file_path), "--json", "-"] # "-" for stdout
        
        # Running on the whole project path is generally better:
        # You might need to specify solc version if not auto-detected well.
        # e.g. --solc <version> or ensure .slither.config.json is present
        command = [
            SLITHER_COMMAND, 
            str(self.project_path), # Analyze the whole project directory
            "--json", "-",
            # "--filter-paths", str(sol_file_path.relative_to(self.project_path)) # To focus output somewhat if needed
        ]
        logger.info(f"Running Slither: {' '.join(command)}")

        try:
            # Slither often needs to be run from the root of the Hardhat/Foundry project
            # or a directory containing the contracts.
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.project_path, text=True)
            stdout, stderr = process.communicate(timeout=300) # 5 min timeout

            if process.returncode != 0:
                # Slither often exits with non-zero code even if it produces JSON (e.g. if findings exist)
                # It might also exit non-zero if there's a legitimate error.
                # SWC-registry related errors are common if it can't fetch, usually ignorable for findings.
                logger.warning(f"Slither exited with code {process.returncode}.")
                logger.debug(f"Slither stderr:\n{stderr}")
                if not stdout.strip() and "CRITICAL" in stderr: # A real error
                    logger.error(f"Slither critical error. stderr: {stderr}")
                    return None
            
            if not stdout.strip():
                logger.info(f"Slither produced no JSON output for {self.project_path}. This might be normal if no issues or due to config.")
                if stderr: logger.debug(f"Slither stderr for no-output case: {stderr}")
                return [] # Return empty list if no JSON but no critical error

            try:
                slither_results = json.loads(stdout)
                if slither_results.get("success") is True and "results" in slither_results:
                    # Filter results for the specific file if we ran on the whole project
                    # This is a basic filter, Slither's output structure can be nested.
                    file_specific_detections = []
                    relative_sol_file_path_str = str(sol_file_path.relative_to(self.project_path))

                    for detection in slither_results["results"].get("detectors", []):
                        # Check if any element's source_mapping matches the file
                        is_in_file = False
                        for element in detection.get("elements", []):
                            if element.get("source_mapping", {}).get("filename_relative") == relative_sol_file_path_str:
                                is_in_file = True
                                break
                        if is_in_file:
                            file_specific_detections.append(detection)

                    logger.info(f"Slither found {len(file_specific_detections)} potential issues in {sol_file_path.name} (from project-wide scan).")
                    return file_specific_detections
                else:
                    logger.warning(f"Slither JSON output structure not as expected or 'success' is false. Output: {stdout[:500]}")
                    if stderr: logger.debug(f"Slither stderr for unexpected JSON: {stderr}")
                    return None # Or an empty list depending on how strict you want to be
            except json.JSONDecodeError:
                logger.error(f"Failed to decode Slither JSON output. stdout: {stdout[:1000]}")
                if stderr: logger.debug(f"Slither stderr for JSON decode error: {stderr}")
                return None

        except subprocess.TimeoutExpired:
            logger.error("Slither command timed out.")
            return None
        except FileNotFoundError:
            logger.error(f"Slither command '{SLITHER_COMMAND}' not found. Make sure it's installed and in your PATH.")
            return None
        except Exception as e:
            logger.error(f"An error occurred while running Slither: {e}")
            return None

    def analyze_project_with_slither(self) -> Optional[Dict[str, Any]]:
        """
        Runs Slither on the entire project and returns the full parsed JSON output.
        """
        command = [SLITHER_COMMAND, str(self.project_path), "--json", "-"]
        logger.info(f"Running Slither on project: {' '.join(command)}")

        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.project_path, text=True)
            stdout, stderr = process.communicate(timeout=600) # 10 min timeout for whole project

            if process.returncode != 0:
                logger.warning(f"Slither (project analysis) exited with code {process.returncode}.")
                logger.debug(f"Slither (project analysis) stderr:\n{stderr}")
                if not stdout.strip() and "CRITICAL" in stderr:
                    logger.error(f"Slither (project analysis) critical error. stderr: {stderr}")
                    return None
            
            if not stdout.strip():
                logger.info(f"Slither (project analysis) produced no JSON output for {self.project_path}.")
                return {"success": True, "results": {"detectors": []}} # Assume success, no findings

            try:
                slither_results = json.loads(stdout)
                if slither_results.get("success") is True and "results" in slither_results:
                    num_detections = len(slither_results["results"].get("detectors", []))
                    logger.info(f"Slither (project analysis) found {num_detections} total potential issues.")
                    return slither_results["results"] # Return just the 'results' part
                else:
                    logger.warning(f"Slither (project analysis) JSON output structure not as expected or 'success' is false. Output: {stdout[:500]}")
                    return None
            except json.JSONDecodeError:
                logger.error(f"Failed to decode Slither (project analysis) JSON output. stdout: {stdout[:1000]}")
                return None

        except subprocess.TimeoutExpired:
            logger.error("Slither (project analysis) command timed out.")
            return None
        except FileNotFoundError:
            logger.error(f"Slither command '{SLITHER_COMMAND}' not found for project analysis.")
            return None
        except Exception as e:
            logger.error(f"An error occurred while running Slither (project analysis): {e}")
            return None