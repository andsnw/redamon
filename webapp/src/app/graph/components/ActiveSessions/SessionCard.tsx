'use client'

import { memo } from 'react'
import { Monitor, Globe, MessageSquare, Skull, ArrowUpCircle, Square } from 'lucide-react'
import type { MsfSession, MsfJob, NonMsfSession } from '@/lib/websocket-types'
import styles from './SessionCard.module.css'

// ── Session card ──

interface SessionCardProps {
  session: MsfSession
  isSelected: boolean
  onSelect: () => void
  onKill: () => void
  onUpgrade: () => void
}

export const SessionCard = memo(function SessionCard({
  session,
  isSelected,
  onSelect,
  onKill,
  onUpgrade,
}: SessionCardProps) {
  const isMeterpreter = session.type === 'meterpreter'

  return (
    <div
      className={`${styles.card} ${isSelected ? styles.cardSelected : ''}`}
      onClick={onSelect}
    >
      <div className={styles.cardHeader}>
        <span className={styles.sessionId}>#{session.id}</span>
        <span className={`${styles.typeBadge} ${isMeterpreter ? styles.meterpreter : styles.shell}`}>
          {isMeterpreter ? 'meterpreter' : 'shell'}
        </span>
      </div>

      <div className={styles.meta}>
        {session.info && (
          <div className={styles.metaRow}>
            <Monitor size={11} />
            <span className={styles.metaValue}>{session.info}</span>
          </div>
        )}
        {session.connection && (
          <div className={styles.metaRow}>
            <Globe size={11} />
            <span className={styles.metaValue}>{session.connection}</span>
          </div>
        )}
        {session.chat_session_id && (
          <div className={styles.metaRow}>
            <MessageSquare size={11} />
            <span className={styles.chatLink} title={session.chat_session_id}>
              {session.chat_session_id.slice(0, 12)}...
            </span>
          </div>
        )}
      </div>

      <div className={styles.actions}>
        <button
          className={`${styles.actionBtn} ${styles.killBtn}`}
          onClick={e => { e.stopPropagation(); onKill() }}
          title="Kill session"
        >
          <Skull size={11} />
          Kill
        </button>
        {!isMeterpreter && (
          <button
            className={`${styles.actionBtn} ${styles.upgradeBtn}`}
            onClick={e => { e.stopPropagation(); onUpgrade() }}
            title="Upgrade to meterpreter"
          >
            <ArrowUpCircle size={11} />
            Upgrade
          </button>
        )}
      </div>
    </div>
  )
})

// ── Non-MSF session card ──

interface NonMsfCardProps {
  session: NonMsfSession
  isSelected: boolean
  onSelect: () => void
}

export const NonMsfCard = memo(function NonMsfCard({
  session,
  isSelected,
  onSelect,
}: NonMsfCardProps) {
  return (
    <div
      className={`${styles.card} ${isSelected ? styles.cardSelected : ''}`}
      onClick={onSelect}
    >
      <div className={styles.cardHeader}>
        <span className={styles.sessionId}>{session.id}</span>
        <span className={`${styles.typeBadge} ${styles.listener}`}>
          {session.tool || session.type}
        </span>
      </div>
      {session.command && (
        <div className={styles.meta}>
          <div className={styles.metaRow}>
            <Monitor size={11} />
            <span className={styles.metaValue}>{session.command}</span>
          </div>
        </div>
      )}
    </div>
  )
})

// ── Job card ──

interface JobCardProps {
  job: MsfJob
  onKill: () => void
}

export const JobCard = memo(function JobCard({ job, onKill }: JobCardProps) {
  return (
    <div className={styles.jobCard}>
      <div className={styles.jobInfo}>
        <span className={styles.jobName}>{job.name}</span>
        {job.port > 0 && (
          <span className={styles.jobMeta}>:{job.port}</span>
        )}
      </div>
      <button
        className={`${styles.actionBtn} ${styles.killBtn}`}
        onClick={onKill}
        title="Stop job"
      >
        <Square size={10} />
        Stop
      </button>
    </div>
  )
})
