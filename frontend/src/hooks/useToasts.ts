import { useCallback, useMemo, useState } from 'react'
import type { Toast, ToastTone } from '../types'

export function useToasts() {
  const [toasts, setToasts] = useState<Toast[]>([])

  const removeToast = useCallback((id: string) => {
    setToasts((current) => current.filter((toast) => toast.id !== id))
  }, [])

  const pushToast = useCallback((message: string, tone: ToastTone = 'info') => {
    const id = crypto.randomUUID()
    setToasts((current) => [...current, { id, message, tone }])

    window.setTimeout(() => {
      setToasts((current) => current.filter((toast) => toast.id !== id))
    }, 2600)
  }, [])

  const actions = useMemo(
    () => ({
      success: (message: string) => pushToast(message, 'success'),
      error: (message: string) => pushToast(message, 'error'),
      info: (message: string) => pushToast(message, 'info'),
    }),
    [pushToast],
  )

  return {
    toasts,
    removeToast,
    ...actions,
  }
}
