# utils/json_cleaner.py
import re
import json
import logging

logger = logging.getLogger(__name__)

def escape_newlines_in_json_strings(s: str) -> str:
    """
    State machine that traverses the JSON string and replaces literal newlines
    inside double-quoted strings with escaped '\\n'.
    """
    in_string = False
    escaped = False
    result = []
    for char in s:
        if char == '"':
            if not escaped:
                in_string = not in_string
            result.append(char)
            escaped = False
        elif char == '\\':
            if in_string:
                escaped = not escaped
            result.append(char)
        elif char == '\n':
            if in_string:
                result.append('\\n')
            else:
                result.append(char)
            escaped = False
        elif char == '\r':
            if in_string:
                result.append('\\r')
            else:
                result.append(char)
            escaped = False
        else:
            result.append(char)
            escaped = False
    return "".join(result)

def clean_json_string(response_text: str) -> str:
    """
    Cleans typical LLM JSON output issues including:
    - Literal newlines inside JSON string values
    - Python-style string concatenation (adjacent double-quoted strings)
    - Trailing commas in arrays or objects
    - Missing commas between properties
    """
    if not response_text:
        return response_text

    # 0. Escape literal newlines inside double-quoted string values first
    response_text = escape_newlines_in_json_strings(response_text)

    # 1. Strip any markdown code blocks
    match = re.search(r"```(?:json)?\s*(.*?)\s*```", response_text, re.DOTALL)
    if match:
        response_text = match.group(1).strip()
    else:
        # Check for first { and last }
        start_idx = response_text.find("{")
        end_idx = response_text.rfind("}")
        if start_idx != -1 and end_idx != -1:
            response_text = response_text[start_idx:end_idx + 1]

    # Matches a double-quoted string literal, handling escaped quotes
    str_pat = r'"(?:[^"\\]|\\.)*"'
    
    # 2. Join python-style adjacent string literals (e.g., "part1" \s* \+? \s* "part2")
    # Crucial: Do NOT concatenate if the second string is a key (i.e. followed by a colon)
    def concat_adjacent(m):
        str1 = m.group(1)
        str2 = m.group(2)
        # Strip outer quotes, concatenate content, and return wrapped in quotes
        return f'"{str1[1:-1]}{str2[1:-1]}"'
        
    pattern = re.compile(f'({str_pat})\\s*\\+?\\s*({str_pat})(?!\\s*:)', re.DOTALL)
    
    old_text = None
    # Apply repeatedly in case of multiple concatenations (e.g. "a" "b" "c")
    iterations = 0
    while old_text != response_text and iterations < 10:
        old_text = response_text
        response_text = pattern.sub(concat_adjacent, response_text)
        iterations += 1

    # 3. Fix missing commas between properties (e.g. "a": "b" "c": "d")
    # This matches: "key1": "val1" \s* "key2":
    prop_pattern = re.compile(f'({str_pat})\\s*:\\s*(({str_pat})|\\d+|true|false|null)\\s*(?=\\s*{str_pat}\\s*:)')
    def add_comma(m):
        return f"{m.group(0)},"
    response_text = prop_pattern.sub(add_comma, response_text)

    # 4. Remove trailing commas before closing braces/brackets
    response_text = re.sub(r',\s*\}', '}', response_text)
    response_text = re.sub(r',\s*\]', ']', response_text)

    return response_text.strip()

def parse_json_safely(response_text: str, default_fallback=None, log_failure: bool = True):
    """
    Tries to clean and parse JSON, falling back to a default value if all attempts fail.
    """
    cleaned = clean_json_string(response_text)
    try:
        return json.loads(cleaned)
    except Exception as e:
        if log_failure:
            logger.warning(f"Failed to parse cleaned JSON: {e}")
        # One last ditch effort: look for a JSON object in the cleaned text
        try:
            match = re.search(r"\{.*\}", cleaned, re.DOTALL)
            if match:
                return json.loads(match.group(0))
        except Exception:
            pass
        return default_fallback
