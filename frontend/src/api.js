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

function qs(params) {
  const entries = Object.entries(params).flatMap(([k, v]) => {
    if (v === '' || v === undefined || v === null || v === false) return []
    if (Array.isArray(v)) return v.length ? [[k, v.join(',')]] : []
    return [[k, String(v)]]
  })
  return new URLSearchParams(entries).toString()
}

// --- v2 alert API ---------------------------------------------------------

export const fetchAlerts = (params) => request(`/api/alerts?${qs(params)}`)
export const fetchAlert = (id) => request(`/api/alerts/${encodeURIComponent(id)}`)
export const fetchAlertStats = () => request('/api/alerts/stats')
export const fetchTimeline = (params) => request(`/api/anomalies/timeline?${qs(params)}`)
export const fetchRiskDistribution = () => request('/api/risk/distribution')
export const fetchMitreTechniques = (params = {}) => request(`/api/mitre/techniques?${qs(params)}`)

export { BASE_URL }
