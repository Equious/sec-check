# utils.py
import logging
import json
from pathlib import Path
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

def setup_logging(level=logging.INFO):
    logging.basicConfig(level=level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def load_json_file(file_path: str | Path) -> list | dict | None:
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
        return None
    except json.JSONDecodeError:
        logger.error(f"Error decoding JSON from file: {file_path}")
        return None
    except Exception as e:
        logger.error(f"An unexpected error occurred while loading {file_path}: {e}")
        return None

def save_json_file(data: list | dict, file_path: str | Path):
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        logger.info(f"Successfully saved data to {file_path}")
    except Exception as e:
        logger.error(f"An unexpected error occurred while saving to {file_path}: {e}")


def read_file_content(file_path: str | Path) -> str | None:
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
        return None
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {e}")
        return None
    
def construct_file_function_list_string(
    file_function_definitions: Dict[str, List[Dict[str, Any]]],
    max_files_to_list: int = 15, # Increased default slightly
    max_functions_per_file: int = 20 # Increased default slightly
) -> str:
    output_lines = []
    files_listed_count = 0

    if not file_function_definitions:
        return "No function definitions available to list."

    for file_path, functions in file_function_definitions.items():
        if files_listed_count >= max_files_to_list:
            output_lines.append(f"... and {len(file_function_definitions) - files_listed_count} more file(s) with function definitions not listed in detail.")
            break
        
        output_lines.append(f"File: {file_path}")
        if not functions:
            output_lines.append("  Functions/Modifiers: (No functions or modifiers extracted for this file, or a parsing error occurred)")
        else:
            func_details_list = []
            listed_function_count_for_file = 0
            for func_def in functions:
                if listed_function_count_for_file >= max_functions_per_file:
                    func_details_list.append(f"    ... and {len(functions) - listed_function_count_for_file} more function(s)/modifier(s) in this file.")
                    break
                
                # Construct the function signature string
                kind = func_def.get('kind', 'function')
                name = func_def.get('name', 'N/A')
                params_str = func_def.get('parameters_str', '')
                visibility = func_def.get('visibility', 'N/A')
                returns_str = func_def.get('return_parameters_str', '')
                
                func_sig_parts = [kind, name]
                
                # Add parameters
                func_sig_parts.append(f"({params_str})")

                # Add visibility (be more selective to avoid clutter for common cases)
                if visibility not in ['default', 'N/A', 'internal', 'private']: # Show public/external by default
                    func_sig_parts.append(visibility)
                elif visibility not in ['default', 'N/A']: # Still show others if explicitly set (like internal/private)
                    func_sig_parts.append(visibility)


                # Add return parameters if they exist
                if returns_str:
                    func_sig_parts.append(f"returns ({returns_str})")

                func_sig = " ".join(func_sig_parts)

                # Add Natspec if available (briefly)
                natspec = func_def.get('natspec')
                if natspec:
                    # Take first line or first 80 chars of Natspec for brevity in the list
                    first_line_natspec = natspec.split('\n')[0][:80].strip()
                    if first_line_natspec: # Only add if Natspec content is not empty after stripping
                        ellipsis = "..." if len(natspec) > 80 or '\n' in natspec.strip() else ""
                        func_sig += f" /* Natspec: @notice {first_line_natspec}{ellipsis} */"

                func_details_list.append(f"  - {func_sig}")
                listed_function_count_for_file += 1

            if not func_details_list and functions: # Case where all functions were beyond max_functions_per_file
                 output_lines.append(f"  Functions/Modifiers: ({len(functions)} total, details truncated due to limit)")
            elif not func_details_list: # Should be covered by the "if not functions:" above
                 output_lines.append("  Functions/Modifiers: (None)")
            else:
                output_lines.extend(func_details_list)
        
        output_lines.append("") # Add a blank line for readability between files
        files_listed_count += 1
        
    return "\n".join(output_lines)

        
        
    return "\n".join(output_lines)