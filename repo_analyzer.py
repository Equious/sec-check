# repo_analyzer.py
import re
import os
import shutil
import subprocess
import logging
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Any
import json # For solc AST output

from git import Repo, GitCommandError
import solcx # Import py-solc-x

from config import WORKSPACE_DIR, GIT_COMMAND, DEFAULT_SOLIDITY_VERSION # Add DEFAULT_SOLIDITY_VERSION to config
from llm_handler import LLMHandler

logger = logging.getLogger(__name__)

class RepoAnalyzer:
    def __init__(self, repo_url: str, llm_handler: LLMHandler):
        self.repo_url = repo_url
        self.llm_handler = llm_handler
        self.repo_name = self._get_repo_name_from_url(repo_url)
        self.local_repo_path = Path(WORKSPACE_DIR) / self.repo_name
        self.solidity_files: List[Path] = []
        self.contract_contents: Dict[str, str] = {}
        self.project_summary: str = "Not yet generated."
        self.detected_standards: List[str] = []
        self.file_function_definitions: Dict[str, List[Dict[str, Any]]] = {}
        self.solc_version_used: Optional[str] = None

    # ... (clone_or_pull_repo, find_solidity_files, read_contract_contents, generate_project_summary, detect_standards_and_patterns are mostly the same)

    def _get_repo_name_from_url(self, url: str) -> str:
        return url.split('/')[-1].replace('.git', '')

    def clone_or_pull_repo(self) -> bool:
        if self.local_repo_path.exists():
            logger.info(f"Repository already exists at {self.local_repo_path}. Pulling latest changes.")
            try:
                repo = Repo(self.local_repo_path)
                origin = repo.remotes.origin
                origin.pull() # Pull first before trying to install deps on potentially old state
                logger.info("Successfully pulled latest changes.")
            except GitCommandError as e:
                logger.error(f"Error pulling repository: {e}. Attempting to re-clone.")
                try:
                    shutil.rmtree(self.local_repo_path)
                except OSError as e_rm:
                    logger.error(f"Error removing existing directory {self.local_repo_path}: {e_rm}. Please remove manually and retry.")
                    return False
                # Fall through to clone
            except Exception as e: # Other Git errors
                logger.error(f"Unexpected error with existing repo during pull: {e}. Compilation might use stale code or fail.")
                # Not returning False here, as we might still try to work with the existing code.
                # Or, decide to return False if a clean pull is essential.

        if not self.local_repo_path.exists(): # Only clone if it doesn't exist (e.g. after rm due to pull error, or first time)
            logger.info(f"Cloning repository {self.repo_url} into {self.local_repo_path}...")
            try:
                Repo.clone_from(self.repo_url, self.local_repo_path)
                logger.info("Repository cloned successfully.")
            except GitCommandError as e:
                logger.error(f"Error cloning repository: {e}")
                if "Authentication failed" in str(e): logger.error("Authentication failed.")
                elif "not found" in str(e): logger.error(f"Repository URL {self.repo_url} not found.")
                return False
            except Exception as e:
                logger.error(f"An unexpected error occurred during cloning: {e}")
                return False
        
        # --- Dependency Installation Step ---
        logger.info(f"Attempting to install project dependencies in {self.local_repo_path}...")

        # Attempt NPM install if package.json exists (covers Hardhat and hybrid Foundry projects)
        package_json_path = self.local_repo_path / "package.json"
        if package_json_path.exists():
            logger.info("Found package.json, attempting 'npm install'...")
            npm_command = shutil.which("npm")
            if npm_command:
                try:
                    # Using --silent or --quiet if too much output, but default is fine for logs
                    # Adding --legacy-peer-deps can sometimes resolve difficult dependency trees
                    # Prefer CI for cleaner installs if available: npm ci
                    subprocess.run(
                        [npm_command, "install", "--no-audit", "--no-fund", "--force"], # --force can be risky but helps with some peer dep issues
                        cwd=self.local_repo_path,
                        check=True, # Raise exception on non-zero exit
                        capture_output=True, # Capture stdout/stderr
                        text=True,
                        timeout=600 # 10 min timeout for npm install
                    )
                    logger.info("'npm install' completed successfully.")
                except subprocess.CalledProcessError as e:
                    logger.error(f"'npm install' failed. Return code: {e.returncode}")
                    logger.error(f"NPM Install STDERR:\n{e.stderr}")
                    logger.error(f"NPM Install STDOUT:\n{e.stdout}")
                    logger.warning("NPM install failed. Some dependencies (e.g., in node_modules) might be missing.")
                except subprocess.TimeoutExpired:
                    logger.error("'npm install' timed out after 10 minutes.")
                except FileNotFoundError: # Should be caught by shutil.which
                    logger.warning("'npm' command not found. Cannot install npm dependencies.")
            else:
                logger.warning("'npm' command not found. Skipping npm dependency installation.")
        else:
            logger.info("No package.json found, skipping 'npm install'.")

        # Attempt Foundry-specific dependency installations if foundry.toml exists
        foundry_toml_path = self.local_repo_path / "foundry.toml"
        if foundry_toml_path.exists():
            logger.info("Found foundry.toml. Attempting 'forge install' and git submodules.")
            forge_command = shutil.which("forge")
            git_command = shutil.which("git")

            if forge_command:
                try:
                    logger.info("Running 'forge install --no-commit'...")
                    subprocess.run(
                        [forge_command, "install"], 
                        cwd=self.local_repo_path, 
                        check=True, 
                        capture_output=True, 
                        text=True,
                        timeout=600 # 10 min timeout
                    )
                    logger.info("'forge install' completed.")
                except subprocess.CalledProcessError as e:
                    logger.error(f"'forge install' failed. Return code: {e.returncode}")
                    logger.error(f"Forge Install STDERR:\n{e.stderr}")
                    logger.error(f"Forge Install STDOUT:\n{e.stdout}")
                except subprocess.TimeoutExpired:
                    logger.error("'forge install' timed out after 10 minutes.")
                except FileNotFoundError:
                    logger.warning("'forge' command not found, cannot run 'forge install'.")
            else:
                logger.warning("'forge' command not found, skipping 'forge install'.")
            
            if git_command:
                gitmodules_path = self.local_repo_path / ".gitmodules"
                if gitmodules_path.exists():
                    logger.info("Found .gitmodules, running 'git submodule update --init --recursive --jobs 4'...")
                    try:
                        subprocess.run(
                            [git_command, "submodule", "update", "--init", "--recursive", "--jobs", "4"], # Added --jobs 4 for parallelism
                            cwd=self.local_repo_path, 
                            check=True, 
                            capture_output=True, 
                            text=True,
                            timeout=600 # 10 min timeout
                        )
                        logger.info("Git submodules updated successfully.")
                    except subprocess.CalledProcessError as e:
                        logger.error(f"'git submodule update' failed. Return code: {e.returncode}")
                        logger.error(f"Git Submodule STDERR:\n{e.stderr}")
                        logger.error(f"Git Submodule STDOUT:\n{e.stdout}")
                    except subprocess.TimeoutExpired:
                        logger.error("'git submodule update' timed out after 10 minutes.")
                    except FileNotFoundError: # Should be caught by shutil.which
                        logger.warning("'git' command not found, cannot update submodules.")
                else:
                    logger.info("No .gitmodules file found, skipping submodule update specific call.")
            else:
                logger.warning("'git' command not found, skipping git submodule update.")
        else:
            logger.info("No foundry.toml found, skipping Foundry-specific dependency installation steps.")
            
        return True # Return True even if some dep installations failed, as core code might still be analyzable

    def find_solidity_files(self) -> None:
        self.solidity_files = list(self.local_repo_path.rglob('*.sol'))
        logger.info(f"Found {len(self.solidity_files)} Solidity files.")
        self.solidity_files = [
            f for f in self.solidity_files
            if not any(excluded in str(f).lower() for excluded in ["test/", "script/", "node_modules/", "lib/", "cache/", "forge-std/", "ds-test/"])
        ] # Added forge-std and ds-test exclusion
        logger.info(f"Filtered to {len(self.solidity_files)} core Solidity files.")

    def read_contract_contents(self) -> None:
        for file_path in self.solidity_files:
            try:
                content = file_path.read_text(encoding='utf-8')
                relative_path = str(file_path.relative_to(self.local_repo_path))
                self.contract_contents[relative_path] = content
            except Exception as e:
                logger.error(f"Error reading content of {file_path}: {e}")
        logger.info(f"Read content for {len(self.contract_contents)} Solidity files.")

    def _detect_solc_version_from_sources(self) -> str:
        """Tries to guess solc version from pragma statements."""
        versions = set()
        for content in self.contract_contents.values():
            for line in content.splitlines():
                if line.strip().startswith("pragma solidity"):
                    # Simple regex to extract version constraints like ^0.8.0 or >=0.7.0 <0.9.0
                    match = re.search(r"pragma solidity\s*([<>=^~]*\d+\.\d+\.\d+)", line)
                    if match:
                        # This is a simplification. Handling complex ranges is harder.
                        # For now, just take the first version part.
                        version_constraint = match.group(1)
                        ver_match = re.search(r"(\d+\.\d+\.\d+)", version_constraint)
                        if ver_match:
                            versions.add(ver_match.group(1))
                    break # Assume one pragma per file for simplicity
        if versions:
            # Return the highest version found, simple sort
            return sorted(list(versions), reverse=True)[0]
        return DEFAULT_SOLIDITY_VERSION # from config.py

    def _get_solc_ast(self, file_path_str: str, file_content: str, solc_version: str) -> Optional[Dict[str, Any]]:
        """Compiles a single file using solc and returns its AST component."""
        try:
            if not solcx.get_installed_solc_versions() or solc_version not in solcx.get_installed_solc_versions():
                logger.info(f"Solc version {solc_version} not found. Attempting to install...")
                solcx.install_solc(solc_version, show_progress=True)
            
            solcx.set_solc_version(solc_version, silent=True)

            # Prepare input for solcx.compile_standard
            # Allow remappings for imports (e.g. @openzeppelin/=lib/openzeppelin-contracts/)
            # This requires knowledge of the project's remappings, often in remappings.txt (Foundry)
            # or hardhat.config.js. For now, basic common ones.
            remappings = [
                "@openzeppelin/=node_modules/@openzeppelin/", # Common for Hardhat/NPM
                "forge-std/=lib/forge-std/src/" # Common for Foundry
            ]
            # Add more remappings if the project uses a remappings.txt
            remappings_file = self.local_repo_path / "remappings.txt"
            if remappings_file.exists():
                try:
                    custom_remappings = remappings_file.read_text().strip().split('\n')
                    remappings.extend(r for r in custom_remappings if r)
                    logger.info(f"Loaded {len(custom_remappings)} remappings from remappings.txt")
                except Exception as e_remap:
                    logger.warning(f"Could not read remappings.txt: {e_remap}")


            input_json = {
                "language": "Solidity",
                "sources": {
                    file_path_str: { # Use the relative path as the key
                        "content": file_content
                    }
                },
                "settings": {
                    "outputSelection": {
                        "*": { # For all contracts in all files
                            "*": ["abi", "evm.bytecode.object"], # Basic outputs
                            "": ["ast"] # Request AST for the source unit
                        }
                    },
                    "remappings": remappings,
                    # Add optimizer settings if needed, or allow import paths
                    "evmVersion": "paris" # Or another appropriate EVM version
                }
            }
            
            # Need to provide all source files if there are imports, solc needs context.
            # For simplicity here, this example tries to compile one file at a time
            # which will fail if it has unresolved imports.
            # A more robust solution compiles the whole project or provides all sources.
            # For now, let's focus on getting AST for individual files that might not have complex imports.
            # OR, pass all sources to compile_standard:
            all_sources_for_compiler = {
                rel_path: {"content": code} for rel_path, code in self.contract_contents.items()
            }
            input_json_all_sources = {
                "language": "Solidity",
                "sources": all_sources_for_compiler,
                 "settings": {
                    "outputSelection": {
                        file_path_str: { # Target specific file for AST if possible with all sources
                            "": ["ast"] 
                        },
                        # Or more broadly:
                        # "*": { "": ["ast"] } # AST for all files
                    },
                    "remappings": remappings,
                    "evmVersion": "paris"
                }
            }
            # To get AST for a specific file when compiling many, you select it in outputSelection.
            # If we want AST for ALL files when compiling all:
            input_json_all_sources["settings"]["outputSelection"] = {"*": {"": ["ast"]}}


            logger.debug(f"Compiling with solc {solc_version} for AST of {file_path_str} (within all sources context)")
            compiled_sol = solcx.compile_standard(input_json_all_sources, allow_paths=str(self.local_repo_path))
            
            # The AST is under sources -> file_path -> ast
            ast_data = compiled_sol.get("sources", {}).get(file_path_str, {}).get("ast")
            if not ast_data:
                logger.warning(f"AST not found for {file_path_str} in solc output.")
                if "errors" in compiled_sol:
                    for error in compiled_sol["errors"]:
                        if error.get("severity") == "error":
                            logger.error(f"Solc compilation error for {file_path_str}: {error.get('formattedMessage', error)}")
                        else:
                            logger.warning(f"Solc compilation warning for {file_path_str}: {error.get('formattedMessage', error)}")

            return ast_data
        except solcx.exceptions.SolcError as e:
            logger.error(f"Solc compilation error for {file_path_str} with version {solc_version}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error getting AST via solc for {file_path_str}: {e}", exc_info=True)
            return None

    def _extract_function_definitions_from_solc_ast_node(self, node: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extracts function-like definitions from a solc AST node."""
        definitions = []
        node_type = node.get("nodeType")
        
        natspec = None
        if "documentation" in node and isinstance(node["documentation"], dict): # solc AST structure
            natspec = node["documentation"].get("text", "").strip()
        elif "documentation" in node and isinstance(node["documentation"], str): # Older solc ASTs
            natspec = node["documentation"].strip()


        if node_type in ["FunctionDefinition", "ModifierDefinition", "ConstructorDefinition", "FallbackDefinition", "ReceiveDefinition"]:
            func_name = node.get("name", "")
            kind = node.get("kind", node_type) # e.g., "constructor", "function", "fallback", "receive"
            if node_type == "ConstructorDefinition": 
                func_name = "constructor"
                kind = "constructor"
            elif node_type == "FallbackDefinition":
                func_name = "fallback"
                kind = "fallback"
            elif node_type == "ReceiveDefinition":
                func_name = "receive"
                kind = "receive"

            visibility = node.get("visibility", "N/A") # "public", "internal", "external", "private"
            
            # Parameters
            param_list = []
            if "parameters" in node and isinstance(node["parameters"], dict) and "parameters" in node["parameters"]:
                for param_node in node["parameters"]["parameters"]:
                    param_list.append(f"{param_node.get('typeName',{}).get('name','unknownType')} {param_node.get('name','')}".strip())
            
            # Return Parameters
            ret_param_list = []
            if "returnParameters" in node and isinstance(node["returnParameters"], dict) and "parameters" in node["returnParameters"]:
                 for ret_param_node in node["returnParameters"]["parameters"]:
                    ret_param_list.append(f"{ret_param_node.get('typeName',{}).get('name','unknownType')} {ret_param_node.get('name','')}".strip())


            definitions.append({
                "name": func_name,
                "kind": kind,
                "visibility": visibility,
                "parameters_str": ", ".join(param_list), # Store as string for simplicity in prompt
                "return_parameters_str": ", ".join(ret_param_list),
                "natspec": natspec,
                "raw_node": node # Keep raw node for potential future deeper analysis
            })

        # Recursively search in children nodes (solc AST uses 'nodes' or specific keys like 'body')
        if "nodes" in node and isinstance(node["nodes"], list):
            for child_node in node["nodes"]:
                if isinstance(child_node, dict):
                    definitions.extend(self._extract_function_definitions_from_solc_ast_node(child_node))
        # Check contract body for definitions as well
        if node_type == "ContractDefinition" and "subNodes" in node: # older format
            for child_node in node["subNodes"]:
                 if isinstance(child_node, dict):
                    definitions.extend(self._extract_function_definitions_from_solc_ast_node(child_node))
        elif node_type == "ContractDefinition" and "nodes" in node: # newer format
             for child_node in node["nodes"]:
                 if isinstance(child_node, dict):
                    definitions.extend(self._extract_function_definitions_from_solc_ast_node(child_node))


        # Also check 'body' for statements block which might contain more nested structures
        # (though function defs are usually direct children of ContractDefinition)
        if "body" in node and isinstance(node["body"], dict):
             definitions.extend(self._extract_function_definitions_from_solc_ast_node(node["body"]))


        return definitions

    def _get_foundry_remappings(self) -> List[str]:
        """
        Executes `forge remappings` in the project directory to get dynamic remappings.
        """
        remappings = []
        forge_command = shutil.which("forge")
        if not forge_command:
            logger.warning("'forge' command not found. Cannot dynamically get remappings. Compilation might fail for imports.")
            # Provide some very common fallbacks if forge isn't available but we know it's a Foundry project
            # This is less ideal but better than nothing.
            common_foundry_libs = self.local_repo_path / "lib"
            if common_foundry_libs.is_dir():
                remappings.extend([
                    f"forge-std/={str(common_foundry_libs / 'forge-std/src/')}",
                    f"ds-test/={str(common_foundry_libs / 'forge-std/lib/ds-test/src/')}", # forge-std includes ds-test
                    # Add other super common ones if necessary, but dynamic is preferred
                    # e.g. "@openzeppelin/=lib/openzeppelin-contracts/contracts/" 
                    # but the actual name 'openzeppelin-contracts' can vary.
                ])
                logger.warning(f"Using fallback remappings due to missing 'forge': {remappings}")
            return remappings

        try:
            logger.info(f"Attempting to get remappings using 'forge remappings' in {self.local_repo_path}")
            process = subprocess.run(
                [forge_command, "remappings"],
                cwd=self.local_repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            output = process.stdout.strip()
            if output:
                remappings = [line.strip() for line in output.split('\n') if line.strip()]
                logger.info(f"Successfully obtained {len(remappings)} remappings from 'forge remappings': {remappings}")
            else:
                logger.warning("'forge remappings' produced no output. No dynamic remappings will be used unless remappings.txt exists.")
        except subprocess.CalledProcessError as e:
            logger.error(f"'forge remappings' command failed: {e.stderr}")
            logger.warning("Falling back to checking remappings.txt or minimal defaults for remappings.")
        except FileNotFoundError: # Should be caught by shutil.which, but as a safeguard
            logger.error("'forge' command not found when trying to get remappings.")
            # Fallback remappings can be added here too, similar to above
            
        # Optionally, still try to read remappings.txt as a supplement or fallback
        # if forge remappings failed or was empty, but forge remappings should be authoritative.
        remappings_file_path = self.local_repo_path / "remappings.txt"
        if not remappings and remappings_file_path.exists(): # Only if forge remappings gave nothing
             logger.info("`forge remappings` was empty/failed, attempting to load from remappings.txt")
             try:
                custom_remappings = remappings_file_path.read_text(encoding='utf-8').strip().split('\n')
                for remap_line in custom_remappings:
                    remap_line = remap_line.strip()
                    if remap_line and '=' in remap_line and remap_line not in remappings:
                        remappings.append(remap_line)
                logger.info(f"Loaded {len(remappings)} remappings from remappings.txt as fallback.")
             except Exception as e_remap:
                logger.warning(f"Could not properly read or parse remappings.txt: {e_remap}")
        
        # Ensure basic remappings if others fail, especially for common libs not always in remappings.txt
        # but expected by solc if they are peer dependencies or complex setups.
        # However, `forge remappings` should ideally list everything needed by the project itself.
        # A common one for Foundry that might not always be in remappings.txt if not directly used by project
        # but by a dependency:
        if not any(r.startswith("ds-test/=") for r in remappings):
             ds_test_path = self.local_repo_path / "lib/forge-std/lib/ds-test/src/"
             if ds_test_path.exists(): # Check if the common path exists
                remappings.append(f"ds-test/={str(ds_test_path)}")


        return remappings

    def parse_solidity_files_and_extract_functions(self) -> None:
        """Parses all Solidity files using solc AST, extracts function definitions."""
        logger.info("Parsing Solidity files using solc AST and extracting function definitions (Foundry focused)...")
        
        self.solc_version_used = self._detect_solc_version_from_sources()
        logger.info(f"Attempting to use solc version: {self.solc_version_used}")

        if not self.contract_contents:
            logger.warning("No contract contents available to parse.")
            return

        all_sources_for_compiler = {
            rel_path: {"content": code} for rel_path, code in self.contract_contents.items()
        }

        dynamic_remappings = self._get_foundry_remappings()
        if not dynamic_remappings:
            logger.warning("No remappings found via 'forge remappings' or remappings.txt. "
                           "Import resolution might fail for complex projects.")
            # Add ultra-minimal fallbacks if truly nothing found
            # These are less likely to be correct than forge's output but provide a last resort
            if (self.local_repo_path / "lib/forge-std/src").exists():
                dynamic_remappings.append(f"forge-std/={self.local_repo_path / 'lib/forge-std/src/'}")
            # It's better to rely on forge remappings or a project's remappings.txt for most cases.
            # For this specific case, since forge remappings did return node_modules paths, we trust those primarily.

        logger.debug(f"Using remappings for solc: {dynamic_remappings}")
        
        project_root_abs_str = str(self.local_repo_path.resolve())

        input_json_all_sources = {
            "language": "Solidity",
            "sources": all_sources_for_compiler,
            "settings": {
                "outputSelection": {"*": {"": ["ast"]}}, 
                "remappings": dynamic_remappings,
                "evmVersion": "paris", 
            }
        }

        compiled_output = None
        try:
            installed_versions = solcx.get_installed_solc_versions()
            if not installed_versions or self.solc_version_used not in installed_versions:
                logger.info(f"Solc version {self.solc_version_used} not found locally. Attempting to install...")
                solcx.install_solc(self.solc_version_used, show_progress=True)
            
            solcx.set_solc_version(self.solc_version_used, silent=True)
            logger.info(f"Compiling all sources with solc {self.solc_version_used} to get ASTs. Project root: {project_root_abs_str}")
            
            # --- CRUCIAL CHANGE: Set base_path ---
            # base_path tells solc where to resolve relative paths in remappings and sources
            # allow_paths is for security, telling solc what it *can* access.
            # We still need allow_paths to grant permission to the lib folder etc.
            # The source file keys (e.g., "src/MyContract.sol") are relative to this base_path.
            
            # Construct allow_paths to include the base_path itself and common subdirs like lib, node_modules
            # These must be absolute paths for solcx's allow_paths.
            allowed_paths_for_solc_compile = [project_root_abs_str]
            # Add lib and node_modules if they exist directly under project_root_abs_str
            # This allows solc to follow imports into these directories if remappings point there correctly.
            for sub_dir_name in ["lib", "node_modules"]:
                sub_dir_path = Path(project_root_abs_str) / sub_dir_name
                if sub_dir_path.is_dir():
                    allowed_paths_for_solc_compile.append(str(sub_dir_path.resolve()))
            
            logger.debug(f"Solc base_path: {project_root_abs_str}")
            logger.debug(f"Solc allow_paths for compile: {allowed_paths_for_solc_compile}")


            compiled_output = solcx.compile_standard(
                input_json_all_sources,
                base_path=project_root_abs_str, # Set the base path for solc operations
                allow_paths=allowed_paths_for_solc_compile, # Allow access to project root & key subdirs
                solc_version=self.solc_version_used
            )
        # ... (rest of the error handling and AST processing logic remains the same) ...
        except solcx.exceptions.SolcError as e:
            logger.error(f"Solc compilation error when getting all ASTs with version {self.solc_version_used}:", exc_info=False)
            logger.error(f"SolcError Details: {e}")
            if hasattr(e, 'message'): logger.error(f"SolcError Message: {e.message}")
            if hasattr(e, 'command'): logger.error(f"Solc Command: {e.command}")
            if hasattr(e, 'stdout_data'): logger.error(f"SOLC STDOUT: {e.stdout_data}")
            if hasattr(e, 'stderr_data'): logger.error(f"SOLC STDERR: {e.stderr_data}")
        except Exception as e:
            logger.error(f"Unexpected error during solc compilation for all ASTs: {e}", exc_info=True)

        # ... (AST processing logic from your previous working version) ...
        if compiled_output and "sources" in compiled_output:
            for relative_path_str in self.contract_contents.keys(): 
                ast_data = compiled_output.get("sources", {}).get(relative_path_str, {}).get("ast")
                if ast_data:
                    logger.debug(f"Successfully obtained solc AST for {relative_path_str}")
                    functions = self._extract_function_definitions_from_solc_ast_node(ast_data)
                    self.file_function_definitions[relative_path_str] = functions
                    logger.debug(f"Extracted {len(functions)} function/modifier definitions from solc AST of {relative_path_str}.")
                else:
                    file_had_error = False
                    if compiled_output.get("errors"):
                        for error in compiled_output["errors"]:
                            error_source_location = error.get("sourceLocation", {}).get("file", "")
                            # Check if the error pertains to the current file being processed or is a general error
                            if error.get("severity") == "error" and (not error_source_location or relative_path_str in error_source_location):
                                logger.error(f"Solc compilation error relevant to {relative_path_str} (prevented AST): {error.get('formattedMessage', error)}")
                                file_had_error = True
                                # Don't break, log all errors relevant to this file or general errors
                    if not file_had_error:
                         logger.warning(f"AST data not found for {relative_path_str} in compiled output, and no specific error logged for it. It might have been excluded or is an interface/library without AST under this selection.")
                    self.file_function_definitions[relative_path_str] = []
        elif compiled_output and "errors" in compiled_output: 
            logger.error("Solc compilation for ASTs produced errors but no 'sources' output. Listing all errors:")
            for error_idx, error in enumerate(compiled_output["errors"]):
                severity = error.get("severity", "info")
                log_func = logger.error if severity == "error" else logger.warning if severity == "warning" else logger.info
                log_func(f"Solc Message {error_idx+1} ({severity}): {error.get('formattedMessage', error)}")
        else: 
            logger.error("Solc compilation for ASTs failed or produced no usable output (no 'sources' or 'errors' field in output).")

        logger.info(f"Finished extracting function definitions using solc AST for {len(self.file_function_definitions)} files (may include files with no functions if parsing failed).")


    def analyze(self) -> bool:
        if not self.clone_or_pull_repo(): return False
        self.find_solidity_files()
        if not self.solidity_files:
            logger.warning("No Solidity files found in the repository. Cannot proceed.")
            return False
        self.read_contract_contents()
        if not self.contract_contents:
            logger.warning("Could not read content from any Solidity file. Cannot proceed.")
            return False
        
        self.parse_solidity_files_and_extract_functions() # Uses solc AST
        self.detect_standards_and_patterns()
        self.generate_project_summary()
        return True

    def detect_standards_and_patterns(self) -> None:
        detected = set()
        for content in self.contract_contents.values():
            content_lower = content.lower()
            if "ierc20" in content_lower or " erc20(" in content_lower or " is erc20 " in content_lower:
                detected.add("ERC20")
            if "ierc721" in content_lower or " erc721(" in content_lower or " is erc721 " in content_lower:
                detected.add("ERC721")
            if "ierc1155" in content_lower or " erc1155(" in content_lower or " is erc1155 " in content_lower:
                detected.add("ERC1155")
            if "proxy" in content_lower or "upgradeable" in content_lower or "uups" in content_lower:
                if "delegatecall" in content_lower and ("implementation" in content_lower or "admin" in content_lower or "erc1967" in content_lower):
                    detected.add("UpgradeableProxy")
        self.detected_standards = list(detected)
        logger.info(f"Detected potential standards/patterns: {self.detected_standards}")

    def generate_project_summary(self) -> None:
        logger.info("Generating project summary using LLM...")
        readme_content = ""
        readme_path = self.local_repo_path / "README.md"
        if readme_path.exists():
            try: readme_content = readme_path.read_text(encoding='utf-8', errors='ignore')[:5000]
            except Exception as e: logger.warning(f"Could not read README.md: {e}")

        prominent_files_str = ", ".join([str(p.relative_to(self.local_repo_path)) for p in self.solidity_files[:5]])
        if not prominent_files_str: prominent_files_str = "N/A"
        
        detected_standards_str = ", ".join(self.detected_standards) if self.detected_standards else 'None detected yet'

        prompt = f"""
        Analyze the following information about a smart contract project and provide a brief, high-level summary (2-3 sentences) of its likely purpose and main components.

        Repository Name: {self.repo_name}
        Prominent Solidity Files: {prominent_files_str}
        Detected Standards/Patterns: {detected_standards_str}
        README.md (first 5000 chars):
        ---
        {readme_content if readme_content else "No README content provided or it was empty."}
        ---
        Based on this, what is the project likely about?
        """
        self.project_summary = self.llm_handler.generate_text(prompt, temperature=0.1, max_output_tokens=512)
        logger.info(f"Generated project summary: {self.project_summary}")