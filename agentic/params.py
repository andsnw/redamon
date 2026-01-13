"""
RedAmon Agent Parameters

Configuration constants for the agent orchestrator.
"""

# =============================================================================
# LLM CONFIGURATION
# =============================================================================

OPENAI_MODEL = "gpt-4.1"

# =============================================================================
# MCP SERVER URLs
# =============================================================================

MCP_CURL_URL = "http://host.docker.internal:8001/sse"
MCP_NAABU_URL = "http://host.docker.internal:8000/sse"
MCP_METASPLOIT_URL = "http://host.docker.internal:8003/sse"

# =============================================================================
# REACT AGENT SETTINGS
# =============================================================================

# Maximum iterations before forcing completion
MAX_ITERATIONS = 100

# Phase transition approval requirements
REQUIRE_APPROVAL_FOR_EXPLOITATION = True
REQUIRE_APPROVAL_FOR_POST_EXPLOITATION = True

# Maximum characters of tool output to send to LLM for analysis
# Large outputs (port scans, vuln reports) are truncated to avoid token limits
TOOL_OUTPUT_MAX_CHARS = 8000

# =============================================================================
# NEO4J SETTINGS
# =============================================================================

# Cypher query retry settings
CYPHER_MAX_RETRIES = 3

# =============================================================================
# DEBUG SETTINGS
# =============================================================================

CREATE_GRAPH_IMAGRE_ON_INIT = True

# =============================================================================
# LOGGING SETTINGS
# =============================================================================

# Log file settings
LOG_MAX_MB = 10  # Maximum size per log file in MB
LOG_BACKUP_COUNT = 5  # Number of backup files to keep (total ~60MB max with 10MB files)

# =============================================================================
# TOOL PHASE RESTRICTIONS
# =============================================================================

# Defines which tools are allowed in each phase
TOOL_PHASE_MAP = {
    "query_graph": ["informational", "exploitation", "post_exploitation"],
    "execute_curl": ["informational", "exploitation", "post_exploitation"],
    "execute_naabu": ["informational", "exploitation", "post_exploitation"],
    # Metasploit tools (all stateful, sharing the same persistent msfconsole)
    "metasploit_console": ["exploitation", "post_exploitation"],  # Legacy name, delegates to msf_execute
    "msf_execute": ["exploitation", "post_exploitation"],  # Primary stateful command execution
    "msf_sessions_list": ["exploitation", "post_exploitation"],  # List active sessions
    "msf_session_run": ["exploitation", "post_exploitation"],  # Run command on session
    "msf_session_interact": ["exploitation", "post_exploitation"],  # Get session info
    "msf_session_close": ["exploitation", "post_exploitation"],  # Close a session
    "msf_status": ["exploitation", "post_exploitation"],  # Get msfconsole status
}


def is_tool_allowed_in_phase(tool_name: str, phase: str) -> bool:
    """Check if a tool is allowed in the given phase."""
    allowed_phases = TOOL_PHASE_MAP.get(tool_name, [])
    return phase in allowed_phases


def get_allowed_tools_for_phase(phase: str) -> list:
    """Get list of tool names allowed in the given phase."""
    return [
        tool_name
        for tool_name, allowed_phases in TOOL_PHASE_MAP.items()
        if phase in allowed_phases
    ]
