<script setup>
import { ref, onMounted } from 'vue'

const stars = ref(null)
const forks = ref(null)

function fmt(n) {
  if (n == null) return '--'
  return n >= 1000 ? (n / 1000).toFixed(1) + 'k' : String(n)
}

onMounted(async () => {
  try {
    const res = await fetch('https://api.github.com/repos/cisco-ai-defense/skill-scanner')
    if (!res.ok) return
    const data = await res.json()
    stars.value = data.stargazers_count
    forks.value = data.forks_count
  } catch {}
})
</script>

<template>
  <div class="gh-stats">
    <a
      class="gh-stats-btn"
      href="https://github.com/cisco-ai-defense/skill-scanner"
      target="_blank"
      rel="noopener noreferrer"
      title="Stars on GitHub"
    >
      <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">
        <path d="M8 .25a.75.75 0 0 1 .673.418l1.882 3.815 4.21.612a.75.75 0 0 1 .416 1.279l-3.046 2.97.719 4.192a.75.75 0 0 1-1.088.791L8 12.347l-3.766 1.98a.75.75 0 0 1-1.088-.79l.72-4.194L.818 6.374a.75.75 0 0 1 .416-1.28l4.21-.611L7.327.668A.75.75 0 0 1 8 .25z"/>
      </svg>
      <span class="gh-stats-count">{{ fmt(stars) }}</span>
    </a>
    <a
      class="gh-stats-btn"
      href="https://github.com/cisco-ai-defense/skill-scanner/fork"
      target="_blank"
      rel="noopener noreferrer"
      title="Fork on GitHub"
    >
      <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">
        <path d="M5 5.372v.878c0 .414.336.75.75.75h4.5a.75.75 0 0 0 .75-.75v-.878a2.25 2.25 0 1 0-1.5 0v.878H6.75v-.878a2.25 2.25 0 1 0-1.5 0ZM8 1.25a1.25 1.25 0 1 0 0 2.5 1.25 1.25 0 0 0 0-2.5Zm-2.75 0a1.25 1.25 0 1 0 0 2.5 1.25 1.25 0 0 0 0-2.5ZM8 12.75a2.25 2.25 0 1 0 0-4.5 2.25 2.25 0 0 0 0 4.5ZM8 9.75a1.25 1.25 0 1 1 0 2.5 1.25 1.25 0 0 1 0-2.5Z"/>
        <path d="M8 7.75v2"/>
      </svg>
      <span class="gh-stats-count">{{ fmt(forks) }}</span>
    </a>
  </div>
</template>

<style scoped>
.gh-stats {
  display: flex;
  align-items: center;
  gap: 2px;
  margin-right: 4px;
}

.gh-stats-btn {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 3px 8px;
  border-radius: 6px;
  font-size: 12px;
  font-weight: 500;
  color: var(--vp-c-text-2);
  text-decoration: none;
  transition: color 0.18s ease, background 0.18s ease;
}

.gh-stats-btn:hover {
  color: var(--vp-c-text-1);
  background: var(--vp-c-default-soft);
}

.gh-stats-btn svg {
  flex-shrink: 0;
}

.gh-stats-count {
  font-variant-numeric: tabular-nums;
}
</style>
