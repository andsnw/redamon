import { NextRequest, NextResponse } from 'next/server'

const AGENT_API_BASE_URL = process.env.AGENT_API_URL || process.env.NEXT_PUBLIC_AGENT_API_URL || 'http://localhost:8080'

// =============================================================================
// REQUEST INTERFACES
// =============================================================================

export interface QueryRequest {
  question: string
  user_id: string
  project_id: string
  session_id: string
}

export interface ApprovalRequest {
  session_id: string
  user_id: string
  project_id: string
  decision: 'approve' | 'modify' | 'abort'
  modification?: string
}

// =============================================================================
// RESPONSE INTERFACES
// =============================================================================

export interface TodoItem {
  id: string
  description: string
  status: 'pending' | 'in_progress' | 'completed' | 'blocked'
  priority: 'high' | 'medium' | 'low'
}

export interface ExecutionStepSummary {
  iteration: number
  phase: string
  thought: string
  tool_name: string | null
  success: boolean
  output_summary: string
}

export interface PhaseTransitionRequest {
  from_phase: string
  to_phase: string
  reason: string
  planned_actions: string[]
  risks: string[]
}

export interface UserQuestionRequest {
  question_id: string
  question: string
  context: string
  format: 'text' | 'single_choice' | 'multi_choice'
  options: string[]
  default_value: string | null
  phase: string
}

export interface QueryResponse {
  // Core response fields
  answer: string
  tool_used: string | null
  tool_output: string | null
  session_id: string
  message_count: number
  error: string | null

  // ReAct state fields
  current_phase: 'informational' | 'exploitation' | 'post_exploitation'
  iteration_count: number
  task_complete: boolean

  // Todo list
  todo_list: TodoItem[]

  // Execution trace summary
  execution_trace_summary: ExecutionStepSummary[]

  // Approval flow fields
  awaiting_approval: boolean
  approval_request: PhaseTransitionRequest | null

  // Q&A flow fields
  awaiting_question: boolean
  question_request: UserQuestionRequest | null
}

// =============================================================================
// API HANDLERS
// =============================================================================

export async function POST(request: NextRequest) {
  try {
    const body: QueryRequest = await request.json()

    if (!body.question || !body.project_id || !body.session_id) {
      return NextResponse.json(
        { error: 'question, project_id, and session_id are required' },
        { status: 400 }
      )
    }

    const response = await fetch(`${AGENT_API_BASE_URL}/query`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    })

    if (!response.ok) {
      const errorText = await response.text()
      return NextResponse.json(
        { error: `Agent API error: ${response.status} - ${errorText}` },
        { status: response.status }
      )
    }

    const data: QueryResponse = await response.json()
    return NextResponse.json(data)
  } catch (error) {
    console.error('Agent query error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Query failed' },
      { status: 500 }
    )
  }
}
