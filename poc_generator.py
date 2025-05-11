# poc_generator.py
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
import subprocess
import time
import os # For path operations

from llm_handler import LLMHandler
# from config import WORKSPACE_DIR # Not directly used here if project_local_path is sufficient

logger = logging.getLogger(__name__)

class PoCGenerator:
    def __init__(self, llm_handler: LLMHandler, project_local_path: Path):
        self.llm_handler = llm_handler
        self.project_local_path: Path = project_local_path # Path to the cloned user's project
        self.project_framework: str = "foundry" # Hardcoded for Foundry
        # self.poc_workspace = project_local_path / "ai_generated_pocs" # We'll place tests in project's test dir
        # self.poc_workspace.mkdir(parents=True, exist_ok=True)
        self.test_dir_in_project: Path = self.project_local_path / "test" # Standard Foundry test directory
        self.test_dir_in_project.mkdir(parents=True, exist_ok=True)


    def _setup_poc_environment(self) -> bool:
        """
        Sets up and verifies the PoC testing environment for a Foundry project.
        """
        logger.info(f"Setting up PoC environment (Foundry project expected at: {self.project_local_path})")

        if not (self.project_local_path / "foundry.toml").exists():
            logger.error(f"No foundry.toml found in {self.project_local_path}. "
                         "This does not appear to be a standard Foundry project. PoC generation may fail.")
            return False # Critical for Foundry

        # Check if 'forge' command is available
        try:
            forge_version_process = subprocess.run(["forge", "--version"], capture_output=True, text=True, check=False)
            if forge_version_process.returncode == 0:
                logger.info(f"Foundry (forge) detected: {forge_version_process.stdout.strip()}")
            else:
                logger.error(f"'forge --version' failed. Is Foundry installed and in PATH? Error: {forge_version_process.stderr}")
                return False
        except FileNotFoundError:
            logger.error("'forge' command not found. Please ensure Foundry is installed and in your system PATH.")
            return False
        
        # Compilation is handled by `forge test`, so no explicit compile here.
        logger.info("Foundry PoC environment setup appears OK.")
        return True


    def _generate_poc_code_with_llm(
        self,
        vulnerability_details: Dict[str, Any],
        vulnerable_code_snippet: str, # Could be the full contract code for context
        contract_name: str,
        contract_relative_path: str, # e.g., "src/MyContract.sol" or "contracts/subdir/MyContract.sol"
        function_name: Optional[str] = None,
        attempt_context: Optional[str] = None # For retry attempts with error feedback
    ) -> Optional[str]:
        """
        Uses LLM to generate Foundry PoC test code (.t.sol).
        """
        logger.info(f"Generating Foundry PoC code for: {vulnerability_details['name']} in {contract_name}")

        poc_template = vulnerability_details.get("poc_exploit_logic_template", []) # From your checklist
        poc_template_str = "\n".join(f"- {step}" for step in poc_template) if poc_template else "No specific PoC logic template available. Determine the best way to demonstrate the exploit."

        # Calculate the relative import path from test/Poc.t.sol to contract_relative_path
        # Example: contract_relative_path = "src/MyVictim.sol"
        # Test file will be at "test/SomePoc.t.sol"
        # Import path should be "../src/MyVictim.sol"
        # os.path.relpath can be tricky. Let's construct it carefully or guide LLM.
        
        # Simplification: Assume standard "src/" and "test/" or "lib/" and "test/"
        # More robust: determine actual contract_dir from contract_relative_path
        contract_file_path_obj = Path(contract_relative_path)
        contract_dir_from_root = contract_file_path_obj.parent # e.g., Path("src") or Path("contracts/core")
        
        # Relative path from 'test' dir to the contract's directory
        # Path("test").parent is project root. Then join with contract_dir_from_root
        # No, this is simpler: if test is test/Poc.t.sol, and contract is src/Contract.sol,
        # the relative path from test/ to src/ is "../src/"
        # Number of "../" depends on depth of test file if we put it in subdirs of "test/".
        # For now, assume PoC test file is directly in "test/".
        
        # A common pattern is `import {ContractName} from "src/Contract.sol";` if remappings are set up in foundry.toml
        # Or `import "../src/Contract.sol";`
        # Let's provide the LLM with the contract's path from project root and let it try to construct the import.
        # We also give it the name of the contract to import.

        foundry_instructions = f"""
        Generate a Foundry test contract in Solidity (e.g., MyContractTest.t.sol).
        The test contract MUST inherit from `forge-std/Test.sol`.
        The target contract to test is named `{contract_name}`.
        It is located at the project path: `{contract_relative_path}`.
        Your generated test contract will be placed in the `test/` directory of the project.
        You MUST correctly import the `{contract_name}`. Common import patterns are:
        - `import "../{contract_relative_path}";` (if `{contract_relative_path}` starts with `src/` or similar top-level dir)
        - Or, if remappings are used (e.g. `@oz/=lib/openzeppelin-contracts/`): `import "@oz/contracts/token/ERC20/ERC20.sol";`
        - Or, if the contract path is like `lib/some-lib/src/Contract.sol`, the import might be `import "some-lib/src/Contract.sol";`
        If `{contract_name}` is the filename (without .sol), the import might just be `import {{ {contract_name} }} from "{contract_relative_path}";`

        The test contract should:
        1. Set up the necessary environment in a `setUp()` function (e.g., deploy the `{contract_name}`, attacker contracts, deal ETH/tokens).
        2. Have a public test function, conventionally named `testExploit_{vulnerability_details['id'].replace('-', '_')}()` or similar, that demonstrates the exploit.
        3. Use Foundry's cheatcodes (`vm.prank`, `vm.deal`, `vm.expectEmit`, `vm.expectRevert`, etc.) effectively.
        4. Include clear assertions (`assertEq`, `assertTrue`, `assertGt`, etc.) to verify the success of the exploit.
        5. If an attacker contract is needed, define it within the same `.t.sol` file or as a separate contract that is imported and deployed. Keep it minimal.

        Example Structure (adapt contract names, paths, and logic):
        ```solidity
        // SPDX-License-Identifier: UNLICENSED
        pragma solidity ^0.8.20; // Or the project's pragma version

        import "forge-std/Test.sol";
        // IMPORTANT: Adjust this import based on the actual contract_relative_path: '{contract_relative_path}'
        import "../{contract_relative_path}"; // Or other valid import for '{contract_name}'

        contract ExploitPoC is Test {{
            {contract_name} internal victimContract;
            // AttackerContract internal attackerContract; // If needed
            address payable internal attacker = payable(address(0x attackers_address_)); // e.g., address(uint160(uint256(keccak256("attacker"))))
            address payable internal someUser = payable(address(0x beef_)); // e.g., address(uint160(uint256(keccak256("user"))))


            function setUp() public {{
                vm.deal(attacker, 10 ether); // Give attacker some ETH
                vm.deal(someUser, 5 ether);

                // Deploy the victim contract
                // victimContract = new {contract_name}(/* constructor arguments */);
                // If deploying as a specific user:
                // vm.prank(owner_of_victim_contract_if_not_test_contract_itself);
                // victimContract = new {contract_name}(/* ... */);


                // Deploy attacker contract if needed:
                // attackerContract = new AttackerContract(address(victimContract));
            }}

            function testExploit_{vulnerability_details['id'].replace('-', '_').replace('.', '_')}() public {{
                // vm.startPrank(attacker); // Start prank for multiple calls

                // 1. Setup initial state for the exploit if necessary
                //    Example: victimContract.deposit{{value: 1 ether}}();

                // 2. Trigger the vulnerable function / interaction pattern
                //    This is where the core exploit logic based on '{vulnerability_details['name']}' goes.
                //    Example: attackerContract.attack();
                //    Example: victimContract.vulnerableFunction( ... );

                // 3. Assert that the exploit was successful
                //    Example: assertEq(address(victimContract).balance, 0, "Victim contract should be drained");
                //    Example: assertTrue(victimContract.isOwner(attacker), "Attacker should now be owner");
                //    Example: assertGt(attacker.balance, initialAttackerBalance, "Attacker balance should increase");

                // vm.stopPrank();
            }}
        }}
        ```
        """

        prompt = f"""
        You are an AI Security Researcher specializing in smart contract vulnerabilities and Foundry testing.
        Your task is to write a complete and executable Foundry Proof of Concept (PoC) test contract (.t.sol file content)
        to exploit the following vulnerability.

        Vulnerability Context:
        - Vulnerability Name/Question: {vulnerability_details['name']}
        - Vulnerability ID: {vulnerability_details['id']}
        - Description: {vulnerability_details['description']}
        - Typical Exploit Logic (if available): {poc_template_str}

        Target Contract Details:
        - Contract Name: `{contract_name}`
        - Location in Project (from project root): `{contract_relative_path}`
        - Vulnerable Code Snippet (from `{contract_name}` for context, may be the full contract):
          ```solidity
          {vulnerable_code_snippet}
          ```
        """
        if function_name:
            prompt += f"- The vulnerability is likely in or related to the function: `{function_name}`.\n"

        if attempt_context: # For retries after failure
            prompt += f"\nPrevious Attempt Context:\n{attempt_context}\nPlease analyze the previous error and generate a corrected PoC.\n"

        prompt += f"""
        {foundry_instructions}

        Provide ONLY the Solidity code for the PoC test contract.
        Do not include any explanations, comments, or markdown formatting outside the code block unless it's part of the Solidity code itself.
        Ensure the PoC is self-contained or correctly imports dependencies available in a standard Foundry project (like forge-std).
        The pragma version should be compatible with modern Foundry projects (e.g., ^0.8.18 or higher, match project if known).
        """

        logger.debug(f"Foundry PoC generation prompt (length: {len(prompt)}, first 500 chars): {prompt[:500]}...")
        poc_code = self.llm_handler.generate_text(prompt, temperature=0.25, max_output_tokens=20000) # More tokens, slightly higher temp for creativity

        # Clean up the response to get just the code block (same logic as before)
        if "```solidity" in poc_code:
            poc_code = poc_code.split("```solidity")[1].split("```")[0].strip()
        elif "```" in poc_code:
            parts = poc_code.split("```")
            if len(parts) > 1:
                poc_code = parts[1].strip() # Assume the first actual block is the code
            else:
                poc_code = poc_code.replace("```", "").strip()
        else:
            logger.warning("LLM response for PoC did not contain ```solidity``` code block markers. Using entire response.")
            poc_code = poc_code.strip()
        
        # Basic sanity check for Solidity code
        if not poc_code or not ("contract " in poc_code and "Test is Test" in poc_code) or poc_code.startswith("Error:") or len(poc_code) < 100 :
            logger.error(f"LLM failed to generate valid-looking Foundry PoC code. Response snippet: {poc_code[:300]}")
            return None

        logger.info(f"LLM generated Foundry PoC code for {vulnerability_details['name']}.")
        return poc_code


    def _run_poc_and_verify(self, poc_file_path_in_project: Path, vulnerability_id: str) -> Tuple[bool, str, str]:
        """
        Runs the generated Foundry PoC test and tries to determine if it was successful.
        Returns (success_bool, stdout, stderr)
        `poc_file_path_in_project` is the absolute path to the PoC test file.
        """
        # `forge test --match-path` expects path relative to project root
        poc_file_relative_to_project = poc_file_path_in_project.relative_to(self.project_local_path)
        
        logger.info(f"Running Foundry PoC: forge test --match-path {poc_file_relative_to_project}")
        command = ["forge", "test", "--match-path", str(poc_file_relative_to_project), "-vv"] # Increased verbosity

        try:
            process = subprocess.run(
                command,
                cwd=self.project_local_path, # Run from the root of the target Foundry project
                capture_output=True,
                text=True,
                timeout=300 # 5 minutes timeout per PoC
            )
            stdout = process.stdout
            stderr = process.stderr # Forge often puts useful compilation errors here too

            full_log = f"STDOUT:\n{stdout}\n\nSTDERR:\n{stderr}"
            logger.debug(full_log)

            # Foundry test success criteria:
            # 1. Exit code 0.
            # 2. STDOUT contains "[PASS]" for the specific test(s).
            # 3. STDOUT contains a summary like "Test result: ok. X passed; 0 failed; ..."
            # Compilation errors will often result in non-zero exit code and errors in stderr/stdout.
            
            if process.returncode == 0:
                if "[PASS]" in stdout and ("0 failed" in stdout.lower() or "no tests failed" in stdout.lower()):
                    logger.info(f"Foundry PoC {poc_file_relative_to_project} likely SUCCEEDED (exit 0, [PASS] and '0 failed' found).")
                    return True, stdout, stderr
                else:
                    logger.warning(f"Foundry PoC {poc_file_relative_to_project} exited 0, but success indicators ([PASS] / '0 failed') not definitively found in stdout.")
                    return False, stdout, stderr # Could be an empty test file or other edge case
            else: # Non-zero exit code
                logger.warning(f"Foundry PoC {poc_file_relative_to_project} FAILED with exit code {process.returncode}.")
                return False, stdout, stderr

        except subprocess.TimeoutExpired:
            logger.error(f"Foundry PoC execution timed out for {poc_file_relative_to_project}")
            return False, "PoC execution timed out.", ""
        except FileNotFoundError: # Should have been caught by _setup_poc_environment
            logger.error("'forge' command not found during PoC execution.")
            return False, "'forge' command not found.", ""
        except Exception as e:
            logger.error(f"Unexpected error running Foundry PoC {poc_file_relative_to_project}: {e}")
            return False, f"Exception during PoC execution: {str(e)}", ""


    def attempt_poc_generation_and_execution(
        self,
        vulnerability_details: Dict[str, Any],
        vulnerable_code_snippet: str,
        full_contract_code: str, # For context if snippet is small
        contract_name: str,
        contract_relative_path: str, # Relative to project root, e.g. "src/MyContract.sol"
        function_name: Optional[str] = None,
        max_retries: int = 2 # Retries for the LLM generation & fix loop
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Main orchestrator for generating, writing, and testing a Foundry PoC.
        Returns (status_str, poc_code_str, full_execution_log_str)
        status_str: "SUCCESS", "FAILURE_EXECUTION", "ERROR_GENERATION", "ERROR_SETUP"
        """
        if not self._setup_poc_environment(): # Simpler call now
            return "ERROR_SETUP", None, "Failed to set up/verify Foundry PoC environment."

        # Use full_contract_code if snippet is too small, or always for better LLM context
        contextual_code_for_llm = full_contract_code if len(vulnerable_code_snippet) < 0.7 * len(full_contract_code) else vulnerable_code_snippet
        
        last_error_context = None

        for attempt in range(max_retries + 1): # max_retries means N actual retries after initial attempt
            logger.info(f"PoC Generation attempt {attempt + 1}/{max_retries + 1} for {vulnerability_details['name']} in {contract_name}")

            poc_code_str = self._generate_poc_code_with_llm(
                vulnerability_details,
                contextual_code_for_llm,
                contract_name,
                contract_relative_path,
                function_name,
                attempt_context=last_error_context # Pass error from previous failed attempt
            )

            if not poc_code_str:
                logger.error("LLM failed to generate PoC code for this attempt.")
                if attempt == max_retries:
                    return "ERROR_GENERATION", None, "LLM failed to generate PoC code after multiple attempts."
                last_error_context = "Previous attempt to generate code returned empty or invalid. Please try again, ensuring full valid Solidity code."
                time.sleep(min(15, 2**(attempt+1))) # Exponential backoff for LLM calls
                continue

            # Sanitize vulnerability ID for filename (dots can be problematic)
            safe_vuln_id = vulnerability_details['id'].replace('.', '_').replace(':', '_')
            poc_filename_base = f"Poc_{safe_vuln_id}_{contract_name}_{int(time.time())}"
            poc_file_path = self.test_dir_in_project / (poc_filename_base + ".t.sol")

            try:
                with open(poc_file_path, "w", encoding="utf-8") as f:
                    f.write(poc_code_str)
                logger.info(f"Foundry PoC code written to {poc_file_path}")
            except Exception as e:
                logger.error(f"Failed to write PoC code to file: {e}")
                # This is an IO error, not necessarily LLM's fault, so don't retry LLM based on this.
                return "ERROR_SETUP", poc_code_str, f"Failed to write PoC code to file: {e}"

            success, exec_stdout, exec_stderr = self._run_poc_and_verify(poc_file_path, vulnerability_details['id'])
            full_execution_log = f"--- STDOUT ---\n{exec_stdout}\n\n--- STDERR ---\n{exec_stderr}"

            if success:
                logger.info(f"Foundry PoC for {vulnerability_details['name']} in {contract_name} VERIFIED successfully.")
                return "SUCCESS", poc_code_str, full_execution_log
            else:
                logger.warning(f"Foundry PoC attempt {attempt + 1} FAILED verification.")
                if attempt == max_retries:
                    logger.error(f"Max retries reached for PoC of {vulnerability_details['name']}. Last execution log:\n{full_execution_log[:1000]}")
                    return "FAILURE_EXECUTION", poc_code_str, full_execution_log
                
                # Prepare context for the next LLM attempt (iterative refinement)
                last_error_context = (
                    f"The previously generated PoC test failed to compile or pass.\n"
                    f"Review the PoC code and the execution logs to identify and fix the issue.\n"
                    f"Failed PoC Code:\n```solidity\n{poc_code_str[:2000]}\n```\n" # Send a snippet of failing code
                    f"Execution STDOUT:\n```\n{exec_stdout[:1000]}\n```\n"
                    f"Execution STDERR:\n```\n{exec_stderr[:1000]}\n```\n"
                    f"Focus on compilation errors, import paths, contract deployment, and assertion logic."
                )
                logger.info(f"Retrying PoC generation with error context (length: {len(last_error_context)}).")
                # poc_file_path.unlink(missing_ok=True) # Optionally delete failed PoC file
                time.sleep(min(20, 3**(attempt+1))) # Exponential backoff for LLM calls with feedback

        return "ERROR_MAX_RETRIES_EXHAUSTED", None, "Max PoC generation retries reached after failures."