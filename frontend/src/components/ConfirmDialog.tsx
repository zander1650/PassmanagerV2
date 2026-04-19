type ConfirmDialogProps = {
  open: boolean
  title: string
  message: string
  confirmLabel: string
  cancelLabel?: string
  tone?: 'danger' | 'default'
  onConfirm: () => void
  onCancel: () => void
}

export function ConfirmDialog({
  open,
  title,
  message,
  confirmLabel,
  cancelLabel = 'Cancel',
  tone = 'default',
  onConfirm,
  onCancel,
}: ConfirmDialogProps) {
  if (!open) {
    return null
  }

  return (
    <div className="dialog-overlay" role="presentation">
      <div className="dialog" role="dialog" aria-modal="true" aria-labelledby="dialog-title">
        <h3 id="dialog-title">{title}</h3>
        <p>{message}</p>
        <div className="dialog-actions">
          <button type="button" className="ghost" onClick={onCancel}>
            {cancelLabel}
          </button>
          <button type="button" className={tone === 'danger' ? 'danger' : ''} onClick={onConfirm}>
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  )
}
