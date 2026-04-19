import { useEffect, useRef } from 'react'

type UseInactivityLockOptions = {
  enabled: boolean
  timeoutMs: number
  onLock: () => void
}

export function useInactivityLock({ enabled, timeoutMs, onLock }: UseInactivityLockOptions) {
  const timeoutRef = useRef<number | null>(null)
  const onLockRef = useRef(onLock)

  onLockRef.current = onLock

  useEffect(() => {
    if (!enabled) {
      if (timeoutRef.current) {
        window.clearTimeout(timeoutRef.current)
      }
      return
    }

    const resetTimer = () => {
      if (timeoutRef.current) {
        window.clearTimeout(timeoutRef.current)
      }

      timeoutRef.current = window.setTimeout(() => {
        onLockRef.current()
      }, timeoutMs)
    }

    const events: Array<keyof WindowEventMap> = [
      'mousemove',
      'keydown',
      'mousedown',
      'touchstart',
      'scroll',
      'focus',
    ]

    events.forEach((eventName) => {
      window.addEventListener(eventName, resetTimer, { passive: true })
    })

    resetTimer()

    return () => {
      if (timeoutRef.current) {
        window.clearTimeout(timeoutRef.current)
      }

      events.forEach((eventName) => {
        window.removeEventListener(eventName, resetTimer)
      })
    }
  }, [enabled, timeoutMs])
}
