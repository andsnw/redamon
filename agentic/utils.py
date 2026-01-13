"""
RedAmon Agent Utility Functions

Helper functions for the LangGraph agent orchestrator.
Includes session management, config creation, and response extraction.
"""

from typing import Dict, Any, List, TYPE_CHECKING

from state import AgentState
from params import MAX_ITERATIONS

if TYPE_CHECKING:
    from langgraph.checkpoint.memory import MemorySaver



_checkpointer: "MemorySaver | None" = None


def set_checkpointer(cp: "MemorySaver") -> None:
    """Set the checkpointer reference (called by orchestrator)."""
    global _checkpointer
    _checkpointer = cp


def get_checkpointer() -> "MemorySaver | None":
    """Get the checkpointer reference."""
    return _checkpointer


def get_thread_id(user_id: str, project_id: str, session_id: str) -> str:
    """
    Create a unique thread_id for the checkpointer from identifiers.

    Args:
        user_id: User identifier
        project_id: Project identifier
        session_id: Session identifier

    Returns:
        Combined thread_id string for checkpointer
    """
    return f"{user_id}:{project_id}:{session_id}"


def parse_thread_id(thread_id: str) -> tuple[str, str, str]:
    """
    Parse a thread_id back into its components.

    Args:
        thread_id: Combined thread_id string

    Returns:
        Tuple of (user_id, project_id, session_id)
    """
    parts = thread_id.split(":", 2)
    if len(parts) == 3:
        return parts[0], parts[1], parts[2]
    return "unknown", "unknown", thread_id


def list_sessions(user_id: str, project_id: str) -> List[str]:
    """
    List all session_ids for a user/project.

    Args:
        user_id: User identifier
        project_id: Project identifier

    Returns:
        List of session_ids
    """
    prefix = f"{user_id}:{project_id}:"
    sessions = []

    cp = get_checkpointer()
    if cp and hasattr(cp, 'storage'):
        for thread_id in cp.storage.keys():
            if thread_id.startswith(prefix):
                session_id = thread_id[len(prefix):]
                sessions.append(session_id)

    return sessions


def clear_session(user_id: str, project_id: str, session_id: str) -> None:
    """
    Clear a specific session from the checkpointer.

    Args:
        user_id: User identifier
        project_id: Project identifier
        session_id: Session identifier
    """
    thread_id = get_thread_id(user_id, project_id, session_id)

    cp = get_checkpointer()
    if cp and hasattr(cp, 'storage') and thread_id in cp.storage:
        del cp.storage[thread_id]


def get_session_count() -> int:
    """Get total number of active sessions."""
    cp = get_checkpointer()
    if cp and hasattr(cp, 'storage'):
        return len(cp.storage)
    return 0


def get_message_count(user_id: str, project_id: str, session_id: str) -> int:
    """
    Get the number of messages in a session.

    Args:
        user_id: User identifier
        project_id: Project identifier
        session_id: Session identifier

    Returns:
        Number of messages in the session
    """
    thread_id = get_thread_id(user_id, project_id, session_id)

    cp = get_checkpointer()
    if cp and hasattr(cp, 'storage') and thread_id in cp.storage:
        checkpoint = cp.storage.get(thread_id)
        if checkpoint and 'channel_values' in checkpoint:
            messages = checkpoint['channel_values'].get('messages', [])
            return len(messages)

    return 0


def create_config(
    user_id: str,
    project_id: str,
    session_id: str
) -> dict:
    """
    Create config for graph invocation with checkpointer thread_id.

    Config contains:
    - thread_id: For MemorySaver checkpointer (session persistence)
    - user_id, project_id, session_id: For logging in nodes

    Args:
        user_id: User identifier
        project_id: Project identifier
        session_id: Session identifier for conversation continuity

    Returns:
        Config dict for graph.invoke()
    """
    thread_id = get_thread_id(user_id, project_id, session_id)

    return {
        # LangGraph recursion limit - must be higher than MAX_ITERATIONS
        # Each iteration may have multiple graph transitions (think -> execute -> analyze)
        "recursion_limit": MAX_ITERATIONS * 5,
        "configurable": {
            "thread_id": thread_id,
            "user_id": user_id,
            "project_id": project_id,
            "session_id": session_id
        }
    }


def get_config_values(config) -> tuple[str, str, str]:
    """
    Extract user_id, project_id, session_id from config.

    Use in nodes for logging:
        user_id, project_id, session_id = get_config_values(config)
        logger.info(f"[{user_id}/{project_id}/{session_id}] Processing...")

    Args:
        config: The config dict or RunnableConfig passed to graph nodes

    Returns:
        Tuple of (user_id, project_id, session_id)
    """
    if config is None:
        return ("unknown", "unknown", "unknown")

    # LangGraph passes RunnableConfig - try multiple ways to access configurable
    configurable = None

    # Method 1: Direct dict access
    if isinstance(config, dict):
        configurable = config.get("configurable", {})
    # Method 2: RunnableConfig object with configurable attribute
    elif hasattr(config, 'configurable'):
        configurable = config.configurable or {}
    # Method 3: Try .get() method (duck typing)
    elif hasattr(config, 'get'):
        configurable = config.get("configurable", {})

    if configurable is None:
        return ("unknown", "unknown", "unknown")

    # Extract values from configurable
    if isinstance(configurable, dict):
        return (
            configurable.get("user_id", "unknown"),
            configurable.get("project_id", "unknown"),
            configurable.get("session_id", "unknown")
        )
    elif hasattr(configurable, 'get'):
        return (
            configurable.get("user_id", "unknown"),
            configurable.get("project_id", "unknown"),
            configurable.get("session_id", "unknown")
        )
    else:
        return (
            getattr(configurable, "user_id", "unknown"),
            getattr(configurable, "project_id", "unknown"),
            getattr(configurable, "session_id", "unknown")
        )


def get_identifiers(state: AgentState, config = None) -> tuple[str, str, str]:
    """
    Get user_id, project_id, session_id from config with state fallback.

    This is the preferred method for nodes - it tries config first,
    then falls back to state values (set by _initialize_node).

    Args:
        state: The AgentState containing user/project/session from initialization
        config: Optional config dict from LangGraph

    Returns:
        Tuple of (user_id, project_id, session_id)
    """
    user_id, project_id, session_id = get_config_values(config)

    # Fallback to state values if config doesn't have them
    if user_id == "unknown":
        user_id = state.get("user_id", "unknown")
    if project_id == "unknown":
        project_id = state.get("project_id", "unknown")
    if session_id == "unknown":
        session_id = state.get("session_id", "unknown")

    return (user_id, project_id, session_id)


def extract_response(state: AgentState) -> Dict[str, Any]:
    """
    Extract the response data from the final state.

    Args:
        state: The final agent state after execution

    Returns:
        Dictionary with answer, tool_used, tool_output, and error fields
    """
    return {
        "answer": state.get("final_answer", ""),
        "tool_used": state.get("tool_used"),
        "tool_output": state.get("tool_output"),
        "error": state.get("error")
    }
