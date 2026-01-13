import { NextRequest, NextResponse } from 'next/server'
import type { QueryResponse } from '../route'

const AGENT_API_BASE_URL = process.env.AGENT_API_URL || process.env.NEXT_PUBLIC_AGENT_API_URL || 'http://localhost:8080'

// =============================================================================
// REQUEST INTERFACE
// =============================================================================

export interface AnswerRequest {
  session_id: string
  user_id: string
  project_id: string
  answer: string
}

// =============================================================================
// API HANDLER
// =============================================================================

export async function POST(request: NextRequest) {
  try {
    const body: AnswerRequest = await request.json()

    // Validate required fields
    if (!body.session_id || !body.user_id || !body.project_id || !body.answer) {
      return NextResponse.json(
        { error: 'session_id, user_id, project_id, and answer are required' },
        { status: 400 }
      )
    }

    const response = await fetch(`${AGENT_API_BASE_URL}/answer`, {
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
    console.error('Agent answer error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Answer failed' },
      { status: 500 }
    )
  }
}
