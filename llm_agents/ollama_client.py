import json
import logging
import urllib.request
import urllib.error
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger(__name__)

DEFAULT_OLLAMA_URL = "http://localhost:11434"

class OllamaMessage:
    def __init__(self, content: str, role: str = "assistant"):
        self.content = content
        self.role = role

class OllamaChoice:
    def __init__(self, message: OllamaMessage):
        self.message = message

class OllamaUsage:
    def __init__(self, prompt_tokens: int = 0, completion_tokens: int = 0):
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens
        self.total_tokens = prompt_tokens + completion_tokens

class OllamaChatResponse:
    def __init__(self, content: str, prompt_tokens: int = 0, completion_tokens: int = 0):
        self.choices = [OllamaChoice(OllamaMessage(content))]
        self.usage = OllamaUsage(prompt_tokens, completion_tokens)

class OllamaCompletions:
    def __init__(self, base_url: str, default_model: str = "qwen2.5-coder:7b", timeout: int = 120):
        self.base_url = base_url.rstrip("/")
        self.default_model = default_model
        self.timeout = timeout

    def create(self, model: Optional[str] = None, messages: Optional[List[Dict[str, str]]] = None, **kwargs) -> OllamaChatResponse:
        model_name = model or self.default_model
        if not messages:
            messages = []

        url = f"{self.base_url}/api/chat"
        payload = {
            "model": model_name,
            "messages": messages,
            "stream": False
        }

        # Transfer options if provided
        options = {}
        if "temperature" in kwargs:
            options["temperature"] = kwargs["temperature"]
        if "top_p" in kwargs:
            options["top_p"] = kwargs["top_p"]
        if options:
            payload["options"] = options

        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data_bytes,
            headers={"Content-Type": "application/json"}
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                if response.status != 200:
                    raise RuntimeError(f"Ollama API request failed with status code {response.status}")
                res_data = json.loads(response.read().decode("utf-8"))

            content = res_data.get("message", {}).get("content", "")
            prompt_tokens = res_data.get("prompt_eval_count", 0) or 0
            completion_tokens = res_data.get("eval_count", 0) or 0

            return OllamaChatResponse(
                content=content,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens
            )
        except urllib.error.URLError as e:
            raise ConnectionError(
                f"Local Ollama is unavailable at {self.base_url}. "
                f"Start Ollama and ensure '{model_name}' is installed. Detail: {e}"
            ) from e
        except Exception as e:
            raise RuntimeError(f"Failed to communicate with local Ollama: {e}") from e

class OllamaChat:
    def __init__(self, base_url: str, default_model: str = "qwen2.5-coder:7b", timeout: int = 120):
        self.completions = OllamaCompletions(base_url, default_model=default_model, timeout=timeout)

class OllamaClient:
    """
    100% Local Ollama Client wrapper providing chat.completions.create interface.
    """
    def __init__(self, base_url: str = DEFAULT_OLLAMA_URL, model: str = "qwen2.5-coder:7b", timeout: int = 120, **kwargs):
        clean_base = base_url if base_url else DEFAULT_OLLAMA_URL
        if clean_base.endswith("/v1"):
            clean_base = clean_base[:-3]
        if clean_base.endswith("/v1/"):
            clean_base = clean_base[:-4]
        self.base_url = clean_base.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.chat = OllamaChat(self.base_url, default_model=self.model, timeout=self.timeout)


def validate_ollama_setup(
    required_models: Optional[List[str]] = None,
    base_url: str = DEFAULT_OLLAMA_URL
) -> Tuple[bool, str]:
    """
    Validate that local Ollama is running and all required models are pulled.
    """
    if required_models is None:
        required_models = ["qwen2.5-coder:7b", "nomic-embed-text:latest"]

    clean_base = base_url if base_url else DEFAULT_OLLAMA_URL
    if clean_base.endswith("/v1"):
        clean_base = clean_base[:-3]
    if clean_base.endswith("/v1/"):
        clean_base = clean_base[:-4]
    clean_base = clean_base.rstrip("/")

    tags_url = f"{clean_base}/api/tags"
    try:
        req = urllib.request.Request(tags_url)
        with urllib.request.urlopen(req, timeout=5) as response:
            if response.status != 200:
                return False, f"Local Ollama server returned status {response.status}"
            data = json.loads(response.read().decode("utf-8"))

        installed_models = [m.get("name", "") for m in data.get("models", [])]
        missing = []
        for req_model in required_models:
            # allow matching nomic-embed-text to nomic-embed-text:latest or vice versa
            base_req = req_model.split(":")[0]
            matched = any(
                inst == req_model or inst.split(":")[0] == base_req
                for inst in installed_models
            )
            if not matched:
                missing.append(req_model)

        if missing:
            return False, f"Local Ollama is running, but missing required model(s): {', '.join(missing)}. Please run 'ollama pull <model_name>'."

        return True, "Local Ollama server and required models are ready."
    except urllib.error.URLError as e:
        return False, f"Local Ollama is unavailable at {clean_base}. Please start Ollama locally. Detail: {e}"
    except Exception as e:
        return False, f"Failed to check local Ollama status: {e}"
