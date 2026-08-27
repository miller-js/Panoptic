const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8080'

async function request(path) {
  let res
  try {
    res = await fetch(`${BASE_URL}${path}`)
  } catch {
    throw new Error(`Can't reach the Panoptic API at ${BASE_URL}`)
  }

  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new Error(body.error || `Request failed (${res.status})`)
  }

  return res.json()
}

function toQueryString(params) {
  const entries = Object.entries(params).filter(
    ([, v]) => v !== '' && v !== undefined && v !== null && v !== false,
  )
  return new URLSearchParams(entries).toString()
}

export function fetchLogs(params) {
  return request(`/api/logs?${toQueryString(params)}`)
}

export function fetchLog(id) {
  return request(`/api/logs/${encodeURIComponent(id)}`)
}

export function fetchStats() {
  return request('/api/stats')
}
