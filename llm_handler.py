# llm_handler.py
import google.generativeai as genai
from config import GEMINI_API_KEY, GEMINI_MODEL_NAME
import logging

logger = logging.getLogger(__name__)

if not GEMINI_API_KEY:
    raise ValueError("GEMINI_API_KEY not found in environment variables.")

genai.configure(api_key=GEMINI_API_KEY)

# For safety settings, you might want to adjust these based on the content
# If you're sending a lot of code that might be flagged, you might need to be more permissive.
# However, be cautious.
# More info: https://ai.google.dev/docs/safety_setting_gemini
DEFAULT_SAFETY_SETTINGS = [
    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
]


class LLMHandler:
    def __init__(self, model_name=GEMINI_MODEL_NAME, safety_settings=None):
        self.model_name = model_name
        self.safety_settings = safety_settings if safety_settings is not None else DEFAULT_SAFETY_SETTINGS
        try:
            self.model = genai.GenerativeModel(
                self.model_name,
                safety_settings=self.safety_settings
            )
            logger.info(f"Gemini model '{self.model_name}' initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to initialize Gemini model: {e}")
            raise

    def generate_text(self, prompt: str, temperature: float = 0.3, max_output_tokens: int = 8192, hint: bool = False) -> str:
        """
        Generates text using the configured Gemini model.
        """
        try:
            generation_config_args = {
                "temperature": temperature,
                "max_output_tokens": max_output_tokens
            }

            # If hint is True, add a hint to the prompt
            if hint:
                generation_config_args["response_mime_type"] = "application/json"

            generation_config = genai.types.GenerationConfig(**generation_config_args)

            response = self.model.generate_content(
                prompt,
                generation_config=generation_config
            )
            print(f"\n\nResponse: {response}\n\n")
            # Handle potential lack of 'text' in response parts, or empty parts
            if response.parts:
                full_text = "".join(part.text for part in response.parts if hasattr(part, 'text'))
                if not full_text.strip() and response.prompt_feedback.block_reason:
                     logger.warning(f"Content blocked. Reason: {response.prompt_feedback.block_reason_message or response.prompt_feedback.block_reason}")
                     return f"Error: Content generation blocked. Reason: {response.prompt_feedback.block_reason_message or response.prompt_feedback.block_reason}"
                return full_text
            elif response.prompt_feedback.block_reason:
                 logger.warning(f"Content blocked. Reason: {response.prompt_feedback.block_reason_message or response.prompt_feedback.block_reason}")
                 return f"Error: Content generation blocked. Reason: {response.prompt_feedback.block_reason_message or response.prompt_feedback.block_reason}"
            else:
                logger.warning("Received an empty response from Gemini with no parts and no block reason.")
                return "Error: Received an empty response from Gemini."

        except Exception as e:
            logger.error(f"Error during Gemini text generation: {e}")
            # Check for specific API related errors if the SDK provides them
            if "API key not valid" in str(e): # Example, adjust based on actual error messages
                return "Error: Invalid Gemini API Key."
            return f"Error: Exception during text generation - {str(e)}"

# Example usage (optional, for testing this file directly)
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    try:
        handler = LLMHandler()
        test_prompt = "Explain the concept of reentrancy in smart contracts in simple terms."
        response_text = handler.generate_text(test_prompt)
        print("LLM Response:")
        print(response_text)
    except Exception as e:
        print(f"Failed to run LLMHandler example: {e}")