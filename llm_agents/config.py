from typing import Dict, Optional, Tuple
from dotenv import load_dotenv

# Agents are also used by the Flask application and utility scripts, not only
# through main.py.  Load the project environment at the shared configuration
# boundary so those supported entry points receive the same Ollama settings.
load_dotenv()

class ModelConfig:
    """
    Configuration class for managing models and API settings across all agents.
    """

    def __init__(
        self,
        analyzer_model: str = "qwen2.5-coder:7b",
        skeptic_model: str = "qwen2.5-coder:7b",
        exploiter_model: str = "qwen2.5-coder:7b",
        generator_model: str = "qwen2.5-coder:7b",
        context_model: str = "qwen2.5-coder:7b",
        base_url: Optional[str] = None,
        skip_poc_generation: bool = False,
        export_markdown: bool = False,
        poc_generation_attempts: int = 3,
        secure_generation_attempts: int = 3,
        poc_max_retries: int = 3,
        forge_build_timeout: int = 30,
        forge_test_timeout: int = 30,
        ollama_request_timeout: int = 180,
    ):
        self.analyzer_model = "qwen2.5-coder:7b" if analyzer_model == "ollama" else analyzer_model
        self.skeptic_model = "qwen2.5-coder:7b" if skeptic_model == "ollama" else skeptic_model
        self.exploiter_model = "qwen2.5-coder:7b" if exploiter_model == "ollama" else exploiter_model
        self.generator_model = "qwen2.5-coder:7b" if generator_model == "ollama" else generator_model
        self.context_model = "qwen2.5-coder:7b" if context_model == "ollama" else context_model
        self.base_url = base_url
        self.skip_poc_generation = skip_poc_generation
        self.export_markdown = export_markdown
        self.poc_generation_attempts = max(1, poc_generation_attempts)
        self.secure_generation_attempts = max(1, poc_generation_attempts)
        self.poc_max_retries = max(0, poc_max_retries)
        self.forge_build_timeout = max(1, forge_build_timeout)
        self.forge_test_timeout = max(1, forge_test_timeout)
        self.ollama_request_timeout = max(10, ollama_request_timeout)

        self.is_reasoning_model = {
            "qwen2.5-coder:7b": False,
        }

        self.model_provider = {
            "qwen2.5-coder:7b": "ollama",
        }

        self.provider_urls = {
            "ollama": "http://localhost:11434",
        }

    def get_model(self, agent_type: str) -> str:
        if agent_type == "analyzer":
            return self.analyzer_model
        elif agent_type == "skeptic":
            return self.skeptic_model
        elif agent_type == "exploiter":
            return self.exploiter_model
        elif agent_type == "generator":
            return self.generator_model
        elif agent_type == "context":
            return self.context_model
        return self.analyzer_model

    def supports_reasoning(self, model_name: str) -> bool:
        return self.is_reasoning_model.get(model_name, False)

    def get_provider_info(self, model_name: str) -> Tuple[str, str, str]:
        provider = "ollama"
        api_key_env = ""
        base_url = self.base_url if self.base_url else "http://localhost:11434"
        return provider, api_key_env, base_url

    def get_openai_args(self, model_name: str = None) -> Dict:
        args = {"base_url": self.base_url or "http://localhost:11434"}
        args.update(timeout=self.ollama_request_timeout)
        return args

