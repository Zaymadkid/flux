import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class MPCConfig:
    mobsf_url: str = os.getenv("MOBSF_URL", "http://localhost:9000")
    mobsf_api_key: Optional[str] = os.getenv("MOBSF_API_KEY")
    jadx_bin: str = os.getenv("JADX_HOME", "jadx")
    jadx_mcp_url: str = os.getenv("JADX_MCP_URL", "http://localhost:8651")
    ghidra_mcp_url: str = os.getenv("GHIDRA_MCP_URL", "http://localhost:8080")
    mcp_port: int = int(os.getenv("MPC_MCP_PORT", "8000"))
    report_dir: str = os.getenv("MPC_REPORT_DIR", "./reports")
    tool_timeout: int = 120
    ghidra_timeout: int = 300

    @classmethod
    def load(cls) -> "MPCConfig":
        return cls()
