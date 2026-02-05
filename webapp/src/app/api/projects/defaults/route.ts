import { NextResponse } from 'next/server'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

// GET /api/projects/defaults - Get default project settings from recon backend
export async function GET() {
  try {
    const response = await fetch(`${RECON_ORCHESTRATOR_URL}/defaults`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
      // Don't cache - always fetch fresh defaults
      cache: 'no-store',
    })

    if (!response.ok) {
      const error = await response.text()
      console.error('Failed to fetch defaults from recon orchestrator:', error)
      return NextResponse.json(
        { error: 'Failed to fetch defaults from recon backend' },
        { status: response.status }
      )
    }

    const defaults = await response.json()
    return NextResponse.json(defaults)
  } catch (error) {
    console.error('Failed to fetch defaults:', error)
    return NextResponse.json(
      { error: 'Failed to connect to recon orchestrator' },
      { status: 503 }
    )
  }
}
