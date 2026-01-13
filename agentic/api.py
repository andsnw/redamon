"""
RedAmon Agent REST API

FastAPI application providing REST endpoints for the ReAct agent orchestrator.
Supports session-based conversation continuity and phase-based approval flow.

Endpoints:
    POST /query - Send a question to the agent
    POST /approve - Approve/reject phase transition
    GET /health - Health check
"""

import logging
from contextlib import asynccontextmanager
from typing import Optional, List, Literal

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from logging_config import setup_logging
from orchestrator import AgentOrchestrator
from utils import get_message_count, get_session_count

# Initialize logging with file rotation
setup_logging(log_level=logging.INFO, log_to_console=True, log_to_file=True)
logger = logging.getLogger(__name__)

orchestrator: Optional[AgentOrchestrator] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.

    Initializes the orchestrator on startup and cleans up on shutdown.
    """
    global orchestrator

    logger.info("Starting RedAmon Agent API...")

    # Initialize orchestrator
    orchestrator = AgentOrchestrator()
    await orchestrator.initialize()

    logger.info("RedAmon Agent API ready")

    yield

    logger.info("Shutting down RedAmon Agent API...")
    if orchestrator:
        await orchestrator.close()


app = FastAPI(
    title="RedAmon Agent API",
    description="REST API for the RedAmon ReAct agent with phase tracking, MCP tools, and Neo4j integration",
    version="2.0.0",
    lifespan=lifespan
)

# Add CORS middleware for webapp
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# REQUEST MODELS
# =============================================================================

class QueryRequest(BaseModel):
    """Request model for agent queries."""
    question: str = Field(..., description="The question to ask the agent", min_length=1)
    user_id: str = Field(..., description="User identifier", min_length=1)
    project_id: str = Field(..., description="Project identifier", min_length=1)
    session_id: str = Field(..., description="Session identifier for conversation continuity", min_length=1)

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "question": "Find vulnerabilities on the target and attempt to exploit them",
                    "user_id": "user1",
                    "project_id": "project1",
                    "session_id": "session-001"
                }
            ]
        }
    }


class ApprovalRequest(BaseModel):
    """Request model for phase transition approval."""
    session_id: str = Field(..., description="Session identifier")
    user_id: str = Field(..., description="User identifier")
    project_id: str = Field(..., description="Project identifier")
    decision: Literal["approve", "modify", "abort"] = Field(
        ..., description="User's decision on the phase transition"
    )
    modification: Optional[str] = Field(
        None, description="User's modification if decision is 'modify'"
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "session_id": "session-001",
                    "user_id": "user1",
                    "project_id": "project1",
                    "decision": "approve",
                    "modification": None
                }
            ]
        }
    }


class AnswerRequest(BaseModel):
    """Request model for user answer to agent question."""
    session_id: str = Field(..., description="Session identifier")
    user_id: str = Field(..., description="User identifier")
    project_id: str = Field(..., description="Project identifier")
    answer: str = Field(..., description="User's answer to the agent's question", min_length=1)

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "session_id": "session-001",
                    "user_id": "user1",
                    "project_id": "project1",
                    "answer": "Use the apache_normalize_path_rce exploit"
                }
            ]
        }
    }


# =============================================================================
# RESPONSE MODELS
# =============================================================================

class PhaseTransitionRequestResponse(BaseModel):
    """Phase transition request details for frontend."""
    from_phase: str
    to_phase: str
    reason: str
    planned_actions: List[str]
    risks: List[str]


class ExecutionStepSummary(BaseModel):
    """Summary of an execution step for frontend display."""
    iteration: int
    phase: str
    thought: str
    tool_name: Optional[str]
    success: bool
    output_summary: str


class TodoItemResponse(BaseModel):
    """Todo item for frontend display."""
    id: str
    description: str
    status: str
    priority: str


class QueryResponse(BaseModel):
    """Response model for agent queries."""
    # Core response fields
    answer: str = Field(..., description="The agent's answer or status message")
    tool_used: Optional[str] = Field(None, description="Name of the tool that was executed")
    tool_output: Optional[str] = Field(None, description="Raw output from the tool")
    session_id: str = Field(..., description="Session identifier (echoed back)")
    message_count: int = Field(..., description="Number of messages in the session")
    error: Optional[str] = Field(None, description="Error message if something went wrong")

    # ReAct state fields
    current_phase: str = Field(
        "informational",
        description="Current agent phase: informational, exploitation, or post_exploitation"
    )
    iteration_count: int = Field(0, description="Current iteration number")
    task_complete: bool = Field(False, description="Whether the task is complete")

    # Todo list for frontend display
    todo_list: List[dict] = Field(
        default_factory=list,
        description="Current task breakdown managed by the LLM"
    )

    # Execution trace summary
    execution_trace_summary: List[dict] = Field(
        default_factory=list,
        description="Summary of recent execution steps"
    )

    # Approval flow fields
    awaiting_approval: bool = Field(
        False,
        description="True if agent is paused waiting for user approval"
    )
    approval_request: Optional[dict] = Field(
        None,
        description="Phase transition request details if awaiting approval"
    )

    # Q&A flow fields
    awaiting_question: bool = Field(
        False,
        description="True if agent is paused waiting for user answer to a question"
    )
    question_request: Optional[dict] = Field(
        None,
        description="Question request details if awaiting_question is True"
    )


class HealthResponse(BaseModel):
    """Response model for health check."""
    status: str
    version: str
    tools_loaded: int
    active_sessions: int


# =============================================================================
# ENDPOINTS
# =============================================================================

@app.post("/query", response_model=QueryResponse, tags=["Agent"])
async def query(request: QueryRequest):
    """
    Send a question to the ReAct agent.

    The agent will:
    1. Initialize or resume the session state
    2. Execute the ReAct loop (Thought → Tool → Output → Analyze)
    3. Track progress with an LLM-managed todo list
    4. Request approval before entering Exploitation or Post-Exploitation phases
    5. Return the result with full state information

    **Session continuity**: Use the same `session_id` to continue a conversation.

    **Phase transitions**: When the agent wants to enter Exploitation or Post-Exploitation,
    it will return `awaiting_approval: true` with an `approval_request` object.
    Use the `/approve` endpoint to respond.
    """
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")

    logger.info(f"Query from {request.user_id}/{request.project_id}/{request.session_id}: {request.question[:50]}...")

    try:
        result = await orchestrator.invoke(
            question=request.question,
            user_id=request.user_id,
            project_id=request.project_id,
            session_id=request.session_id
        )

        message_count = get_message_count(
            request.user_id, request.project_id, request.session_id
        )

        return QueryResponse(
            answer=result.answer,
            tool_used=result.tool_used,
            tool_output=result.tool_output,
            session_id=request.session_id,
            message_count=message_count,
            error=result.error,
            current_phase=result.current_phase,
            iteration_count=result.iteration_count,
            task_complete=result.task_complete,
            todo_list=result.todo_list,
            execution_trace_summary=result.execution_trace_summary,
            awaiting_approval=result.awaiting_approval,
            approval_request=result.approval_request,
            awaiting_question=result.awaiting_question,
            question_request=result.question_request,
        )

    except Exception as e:
        logger.error(f"Error processing query: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/approve", response_model=QueryResponse, tags=["Agent"])
async def approve(request: ApprovalRequest):
    """
    Respond to a phase transition approval request.

    When the agent wants to transition to Exploitation or Post-Exploitation phase,
    it pauses and waits for user approval. Use this endpoint to:

    - **approve**: Allow the transition and continue execution
    - **modify**: Provide feedback to adjust the approach (agent stays in current phase)
    - **abort**: Cancel the transition and end the session

    The response follows the same format as `/query`, allowing the frontend
    to continue displaying the conversation.
    """
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")

    logger.info(f"Approval from {request.user_id}/{request.project_id}/{request.session_id}: {request.decision}")

    try:
        result = await orchestrator.resume_after_approval(
            session_id=request.session_id,
            user_id=request.user_id,
            project_id=request.project_id,
            decision=request.decision,
            modification=request.modification,
        )

        message_count = get_message_count(
            request.user_id, request.project_id, request.session_id
        )

        return QueryResponse(
            answer=result.answer,
            tool_used=result.tool_used,
            tool_output=result.tool_output,
            session_id=request.session_id,
            message_count=message_count,
            error=result.error,
            current_phase=result.current_phase,
            iteration_count=result.iteration_count,
            task_complete=result.task_complete,
            todo_list=result.todo_list,
            execution_trace_summary=result.execution_trace_summary,
            awaiting_approval=result.awaiting_approval,
            approval_request=result.approval_request,
            awaiting_question=result.awaiting_question,
            question_request=result.question_request,
        )

    except Exception as e:
        logger.error(f"Error processing approval: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/answer", response_model=QueryResponse, tags=["Agent"])
async def answer(request: AnswerRequest):
    """
    Respond to an agent's question.

    When the agent needs clarification during execution (e.g., which exploit to use,
    which session to interact with), it pauses and asks the user a question.
    Use this endpoint to provide the answer.

    The response follows the same format as `/query`, allowing the frontend
    to continue displaying the conversation.
    """
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")

    logger.info(f"Answer from {request.user_id}/{request.project_id}/{request.session_id}: {request.answer[:50]}...")

    try:
        result = await orchestrator.resume_after_answer(
            session_id=request.session_id,
            user_id=request.user_id,
            project_id=request.project_id,
            answer=request.answer,
        )

        message_count = get_message_count(
            request.user_id, request.project_id, request.session_id
        )

        return QueryResponse(
            answer=result.answer,
            tool_used=result.tool_used,
            tool_output=result.tool_output,
            session_id=request.session_id,
            message_count=message_count,
            error=result.error,
            current_phase=result.current_phase,
            iteration_count=result.iteration_count,
            task_complete=result.task_complete,
            todo_list=result.todo_list,
            execution_trace_summary=result.execution_trace_summary,
            awaiting_approval=result.awaiting_approval,
            approval_request=result.approval_request,
            awaiting_question=result.awaiting_question,
            question_request=result.question_request,
        )

    except Exception as e:
        logger.error(f"Error processing answer: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health():
    """
    Health check endpoint.

    Returns the API status, version, number of loaded tools, and active sessions.
    """
    tools_count = 0
    if orchestrator and orchestrator.tool_executor:
        tools_count = len(orchestrator.tool_executor.get_all_tools())

    sessions_count = get_session_count()

    return HealthResponse(
        status="ok" if orchestrator and orchestrator._initialized else "initializing",
        version="2.0.0",
        tools_loaded=tools_count,
        active_sessions=sessions_count
    )
