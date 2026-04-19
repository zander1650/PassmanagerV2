import type { Toast } from '../types'

type ToastRegionProps = {
  toasts: Toast[]
  onDismiss: (id: string) => void
}

export function ToastRegion({ toasts, onDismiss }: ToastRegionProps) {
  return (
    <div className="toast-region" aria-live="polite" aria-atomic="false">
      {toasts.map((toast) => (
        <div key={toast.id} className={`toast ${toast.tone}`} role="status">
          <span>{toast.message}</span>
          <button type="button" className="toast-dismiss" onClick={() => onDismiss(toast.id)}>
            Dismiss
          </button>
        </div>
      ))}
    </div>
  )
}
