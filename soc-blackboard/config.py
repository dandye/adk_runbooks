"""
Configuration management for SOC Blackboard system.
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass
from dotenv import load_dotenv


@dataclass
class SecurityToolsConfig:
    """Configuration for MCP security tools."""
    chronicle_project_id: Optional[str] = None
    chronicle_customer_id: Optional[str] = None
    chronicle_region: str = "us"
    soar_url: Optional[str] = None
    soar_app_key: Optional[str] = None
    vt_apikey: Optional[str] = None


@dataclass
class InvestigationConfig:
    """Configuration for investigation parameters."""
    max_investigation_duration: int = 3600  # seconds
    default_confidence_threshold: float = 0.7
    enable_auto_correlation: bool = True
    report_format: str = "markdown"


@dataclass
class BlackboardConfig:
    """Configuration for blackboard behavior."""
    retention_days: int = 90
    max_findings_per_area: int = 1000
    enable_finding_deduplication: bool = True


@dataclass
class AgentConfig:
    """Configuration for agent behavior."""
    agent_timeout: int = 300  # seconds
    enable_parallel_execution: bool = True
    max_parallel_agents: int = 5


@dataclass
class LoggingConfig:
    """Configuration for logging."""
    log_level: str = "INFO"
    log_file: str = "soc_blackboard.log"
    enable_console_logging: bool = True


@dataclass
class SOCBlackboardConfig:
    """Complete configuration for SOC Blackboard system."""
    google_api_key: str
    security_tools: SecurityToolsConfig
    investigation: InvestigationConfig
    blackboard: BlackboardConfig
    agents: AgentConfig
    logging: LoggingConfig
    
    @classmethod
    def load_from_env(cls, env_file: Optional[Path] = None) -> 'SOCBlackboardConfig':
        """Load configuration from environment variables."""
        
        if env_file and env_file.exists():
            load_dotenv(env_file)
        
        # Required configuration
        google_api_key = os.getenv("GOOGLE_API_KEY")
        if not google_api_key:
            raise ValueError("GOOGLE_API_KEY environment variable is required")
        
        # Security tools configuration
        security_tools = SecurityToolsConfig(
            chronicle_project_id=os.getenv("CHRONICLE_PROJECT_ID"),
            chronicle_customer_id=os.getenv("CHRONICLE_CUSTOMER_ID"),
            chronicle_region=os.getenv("CHRONICLE_REGION", "us"),
            soar_url=os.getenv("SOAR_URL"),
            soar_app_key=os.getenv("SOAR_APP_KEY"),
            vt_apikey=os.getenv("VT_APIKEY")
        )
        
        # Investigation configuration
        investigation = InvestigationConfig(
            max_investigation_duration=int(os.getenv("MAX_INVESTIGATION_DURATION", "3600")),
            default_confidence_threshold=float(os.getenv("DEFAULT_CONFIDENCE_THRESHOLD", "0.7")),
            enable_auto_correlation=os.getenv("ENABLE_AUTO_CORRELATION", "true").lower() == "true",
            report_format=os.getenv("REPORT_FORMAT", "markdown")
        )
        
        # Blackboard configuration
        blackboard = BlackboardConfig(
            retention_days=int(os.getenv("BLACKBOARD_RETENTION_DAYS", "90")),
            max_findings_per_area=int(os.getenv("MAX_FINDINGS_PER_AREA", "1000")),
            enable_finding_deduplication=os.getenv("ENABLE_FINDING_DEDUPLICATION", "true").lower() == "true"
        )
        
        # Agent configuration
        agents = AgentConfig(
            agent_timeout=int(os.getenv("AGENT_TIMEOUT", "300")),
            enable_parallel_execution=os.getenv("ENABLE_PARALLEL_EXECUTION", "true").lower() == "true",
            max_parallel_agents=int(os.getenv("MAX_PARALLEL_AGENTS", "5"))
        )
        
        # Logging configuration
        logging_config = LoggingConfig(
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            log_file=os.getenv("LOG_FILE", "soc_blackboard.log"),
            enable_console_logging=os.getenv("ENABLE_CONSOLE_LOGGING", "true").lower() == "true"
        )
        
        return cls(
            google_api_key=google_api_key,
            security_tools=security_tools,
            investigation=investigation,
            blackboard=blackboard,
            agents=agents,
            logging=logging_config
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            "google_api_key": "***masked***",  # Don't expose API key
            "security_tools": self.security_tools.__dict__,
            "investigation": self.investigation.__dict__,
            "blackboard": self.blackboard.__dict__,
            "agents": self.agents.__dict__,
            "logging": self.logging.__dict__
        }
    
    def validate(self) -> bool:
        """Validate configuration completeness."""
        # Check required fields
        if not self.google_api_key:
            return False
        
        # Check numeric ranges
        if self.investigation.max_investigation_duration <= 0:
            return False
        
        if not (0.0 <= self.investigation.default_confidence_threshold <= 1.0):
            return False
        
        if self.blackboard.retention_days <= 0:
            return False
        
        if self.agents.agent_timeout <= 0:
            return False
        
        if self.agents.max_parallel_agents <= 0:
            return False
        
        return True


def get_default_config() -> SOCBlackboardConfig:
    """Get default configuration with environment variable loading."""
    config_file = Path(__file__).parent / ".env"
    return SOCBlackboardConfig.load_from_env(config_file)


def setup_logging(config: LoggingConfig):
    """Set up logging based on configuration."""
    import logging
    import colorlog
    
    # Set logging level
    log_level = getattr(logging, config.log_level.upper(), logging.INFO)
    
    # Create formatters
    console_formatter = colorlog.ColoredFormatter(
        "%(log_color)s%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    file_formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    # Configure root logger
    logger = logging.getLogger()
    logger.setLevel(log_level)
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Console handler
    if config.enable_console_logging:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(console_formatter)
        console_handler.setLevel(log_level)
        logger.addHandler(console_handler)
    
    # File handler
    if config.log_file:
        file_handler = logging.FileHandler(config.log_file)
        file_handler.setFormatter(file_formatter)
        file_handler.setLevel(log_level)
        logger.addHandler(file_handler)
    
    return logger