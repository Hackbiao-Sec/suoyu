<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import PageHead from '@/components/PageHead.vue'
import Icon from '@/components/Icon.vue'
import { listVulns, vulnStats } from '@/api/endpoints'

const route = useRoute()

const items = ref([])
const total = ref(0)
const stats = ref({ total: 0, buckets: [], templates: [], roots: [] })
const loading = ref(false)
const error = ref('')
const detail = ref(null)

const filters = ref({
  severity: '',
  template: '',
  root_domain: '',
  keyword: '',
  task_id: route.query.task || '',
  order: 'time',
})
const offset = ref(0)
const limit = 100

const SEVERITY_LABEL = {
  critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息', unknown: '未标',
}
const SEVERITY_TAG = {
  critical: 'err', high: 'warn', medium: 'cyan', low: 'info', info: 'ok', unknown: '',
}
const SEVERITY_ICON = {
  critical: 'bolt', high: 'alert', medium: 'shield', low: 'file', info: 'file', unknown: 'file',
}

const buckets = computed(() => stats.value.buckets || [])
const pages = computed(() => Math.max(1, Math.ceil(total.value / limit)))
const page = computed(() => Math.floor(offset.value / limit) + 1)
const activeCount = computed(() => buckets.value.reduce((s, b) => s + (b.count || 0), 0))
const scopeChips = computed(() => {
  const out = []
  if (filters.value.severity) out.push(['severity', `等级：${sevLabel(filters.value.severity)}`])
  if (filters.value.template) out.push(['template', `模板：${filters.value.template}`])
  if (filters.value.root_domain) out.push(['root_domain', `根域：${filters.value.root_domain}`])
  if (filters.value.keyword) out.push(['keyword', `关键词：${filters.value.keyword}`])
  if (filters.value.task_id) out.push(['task_id', `任务：${filters.value.task_id}`])
  return out
})

let seqNo = 0

function sevLabel(s) {
  return SEVERITY_LABEL[s] || s || '未标'
}

function fmtTime(ts) {
  if (!ts) return '-'
  const d = new Date(ts * 1000)
  const p = (n) => String(n).padStart(2, '0')
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

async function load() {
  const seq = ++seqNo
  loading.value = true
  error.value = ''
  try {
    const params = {
      severity: filters.value.severity || undefined,
      template: filters.value.template || undefined,
      root_domain: filters.value.root_domain || undefined,
      keyword: filters.value.keyword.trim() || undefined,
      task_id: filters.value.task_id || undefined,
      order: filters.value.order,
      limit,
      offset: offset.value,
    }
    const [list, st] = await Promise.all([listVulns(params), vulnStats({
      root_domain: filters.value.root_domain || undefined,
      keyword: filters.value.keyword.trim() || undefined,
      task_id: filters.value.task_id || undefined,
    })])
    if (seq !== seqNo) return
    items.value = list.items || []
    total.value = list.total || 0
    stats.value = {
      total: st.total || 0,
      buckets: st.buckets || [],
      templates: st.templates || [],
      roots: st.roots || [],
    }
  } catch (e) {
    if (seq !== seqNo) return
    error.value = e?.response?.data?.detail || e.message || '风险漏洞加载失败'
  } finally {
    if (seq === seqNo) loading.value = false
  }
}

function pick(key, value) {
  filters.value[key] = filters.value[key] === value ? '' : value
  offset.value = 0
  load()
}

function dropFilter(key) {
  filters.value[key] = ''
  offset.value = 0
  load()
}

function applySearch() {
  offset.value = 0
  load()
}

function pickSeverity(key) {
  pick('severity', key)
}

function goPage(n) {
  offset.value = (n - 1) * limit
  load()
}

function openTask() {
  if (filters.value.task_id) {
    filters.value.task_id = ''
    offset.value = 0
    load()
  }
}

function copy(text) {
  try { navigator.clipboard.writeText(text || '') } catch (e) { /* 忽略：剪贴板被浏览器拦了不影响查看 */ }
}

function download(name, text) {
  const blob = new Blob(['\ufeff' + text], { type: 'text/csv;charset=utf-8' })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = name
  a.click()
  setTimeout(() => URL.revokeObjectURL(a.href), 4000)
}

function exportCsv() {
  const head = ['等级', '模板', '名称', '命中地址', '主机', '根域', '最近发现']
  const lines = [head.join(',')]
  for (const it of items.value) {
    const row = [sevLabel(it.severity), it.template, it.name, it.matched || it.url, it.host,
      it.root_domain, fmtTime(it.last_seen)]
    lines.push(row.map((v) => `"${String(v == null ? '' : v).replace(/"/g, '""')}"`).join(','))
  }
  download('suoyu_vulns.csv', lines.join('\r\n'))
}

function extraFields(it) {
  const out = Object.entries(it.extra || {})
  if (!out.length) return [['命中地址', it.matched || it.url]]
  return out
}

onMounted(load)
</script>

<template>
  <div class="stack">
    <PageHead
      title="风险漏洞"
      desc="nuclei 扫出来的命中结果：任务里勾了 nuclei 深度探测才往里写；这里按等级、模板、根域筛，点一条看完整命中信息">
      <template #actions>
        <button class="btn sm" @click="load"><Icon name="refresh" :size="13" />刷新</button>
        <button class="btn sm" :disabled="!items.length" @click="exportCsv"><Icon name="download" :size="13" />导出 CSV</button>
      </template>
    </PageHead>

    <div class="metric-row">
      <div class="metric clickable" @click="filters.severity = ''; applySearch()">
        <div class="metric-label">漏洞总量</div>
        <div class="metric-value mono">{{ activeCount.toLocaleString() }}</div>
        <div class="metric-foot">{{ filters.task_id ? `任务 ${filters.task_id}` : '全部任务' }} · 命中条数</div>
      </div>
      <div v-for="b in buckets" :key="b.key" class="metric clickable" @click="pickSeverity(b.key)">
        <div class="metric-label"><Icon :name="SEVERITY_ICON[b.key] || 'alert'" :size="12" />{{ sevLabel(b.key) }}</div>
        <div class="metric-value mono">{{ b.count.toLocaleString() }}</div>
        <div class="metric-foot">{{ filters.severity === b.key ? '已筛选，再点取消' : '点一下只看这一档' }}</div>
      </div>
    </div>

    <div v-if="error" class="panel" style="border-color: rgba(255, 100, 112, 0.36)">
      <div class="panel-body" style="color: var(--red-ink); font-size: 12px">{{ error }}</div>
    </div>

    <div v-if="scopeChips.length" class="scope-row">
      <span v-for="c in scopeChips" :key="c[0]" class="chip on">
        {{ c[1] }}
        <button class="chip-x" @click="dropFilter(c[0])">×</button>
      </span>
      <button v-if="filters.task_id" class="link-btn" @click="openTask">看全部任务</button>
    </div>

    <div class="flex gap-14" style="align-items: flex-start">
      <div class="panel" style="width: 210px; flex: 0 0 auto">
        <div class="panel-head"><span><Icon name="filter" :size="13" />筛选</span></div>
        <div class="panel-body" style="max-height: calc(100vh - 360px); overflow-y: auto">
          <div class="facet-title">等级</div>
          <button class="facet" :class="{ on: !filters.severity }" @click="filters.severity = ''; applySearch()">
            <span class="ellipsis">全部等级</span><span class="mono muted">{{ activeCount }}</span>
          </button>
          <button v-for="b in buckets" :key="b.key" class="facet" :class="{ on: filters.severity === b.key }"
                  @click="pick('severity', b.key)">
            <span class="ellipsis">{{ sevLabel(b.key) }}</span><span class="mono muted">{{ b.count }}</span>
          </button>

          <div class="facet-title">模板</div>
          <button v-for="t in stats.templates.slice(0, 20)" :key="t.value" class="facet"
                  :class="{ on: filters.template === t.value }" @click="pick('template', t.value)">
            <span class="ellipsis mono" :title="t.value">{{ t.value }}</span><span class="mono muted">{{ t.count }}</span>
          </button>
          <div v-if="!stats.templates.length" class="muted" style="font-size: 11px">还没有模板命中</div>

          <div class="facet-title">根域</div>
          <button v-for="r in stats.roots.slice(0, 20)" :key="r.value" class="facet"
                  :class="{ on: filters.root_domain === r.value }" @click="pick('root_domain', r.value)">
            <span class="ellipsis mono" :title="r.value">{{ r.value }}</span><span class="mono muted">{{ r.count }}</span>
          </button>
          <div v-if="!stats.roots.length" class="muted" style="font-size: 11px">还没有根域信息</div>
        </div>
      </div>

      <div class="panel flex-1" style="min-width: 0">
        <div class="panel-head">
          <span><Icon name="alert" :size="13" /><span class="mono">{{ total.toLocaleString() }}</span> 条命中</span>
          <div class="flex gap-8">
            <input v-model="filters.keyword" class="input" style="width: 200px"
                   placeholder="模板 / 名称 / 命中地址" @keyup.enter="applySearch" />
            <select v-model="filters.order" class="select" style="width: 108px" @change="applySearch">
              <option value="time">按时间</option>
              <option value="severity">按等级</option>
            </select>
            <button class="btn xs" @click="applySearch"><Icon name="search" :size="11" />筛选</button>
            <span class="mono muted" style="font-size: 10.5px">{{ page }} / {{ pages }}</span>
            <button class="btn xs" :disabled="page <= 1" @click="goPage(page - 1)">上一页</button>
            <button class="btn xs" :disabled="page >= pages" @click="goPage(page + 1)">下一页</button>
          </div>
        </div>
        <div class="table-wrap">
          <table class="table">
            <thead>
              <tr>
                <th style="width: 74px">等级</th>
                <th>模板</th>
                <th>名称</th>
                <th>命中地址</th>
                <th style="width: 150px">主机</th>
                <th style="width: 150px">根域</th>
                <th style="width: 108px">最近发现</th>
                <th style="width: 66px"></th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="it in items" :key="it.id">
                <td><span class="tag" :class="SEVERITY_TAG[it.severity] || ''">{{ sevLabel(it.severity) }}</span></td>
                <td class="mono ellipsis" style="max-width: 200px" :title="it.template">{{ it.template || '-' }}</td>
                <td class="ellipsis" style="max-width: 220px" :title="it.name">{{ it.name || '-' }}</td>
                <td class="mono ellipsis cell-url" :title="it.matched || it.url">{{ it.matched || it.url }}</td>
                <td class="mono muted ellipsis" :title="it.host">{{ it.host || '-' }}</td>
                <td class="mono muted ellipsis" :title="it.root_domain">{{ it.root_domain || '-' }}</td>
                <td class="mono muted">{{ fmtTime(it.last_seen) }}</td>
                <td style="text-align: right">
                  <button class="btn xs" @click="detail = it"><Icon name="eye" :size="11" />详情</button>
                </td>
              </tr>
              <tr v-if="!items.length && !loading">
                <td colspan="8">
                  <div class="empty">
                    <Icon name="alert" :size="22" />
                    还没有 nuclei 命中。到「策略配置」或任务的深度探测里打开 nuclei，跑完这一页就会出现结果
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <div v-if="detail" class="overlay" @click.self="detail = null">
      <div class="modal">
        <div class="modal-head">
          <Icon name="alert" :size="15" style="color: var(--cyan)" />
          <span class="flex-1 ellipsis">{{ detail.template || detail.name }}</span>
          <button class="btn ghost sm" @click="detail = null"><Icon name="close" :size="13" /></button>
        </div>
        <div class="modal-body">
          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px">
            <div class="field">
              <span class="field-label">等级</span>
              <span><span class="tag" :class="SEVERITY_TAG[detail.severity] || ''">{{ sevLabel(detail.severity) }}</span></span>
            </div>
            <div class="field">
              <span class="field-label">最近发现</span>
              <span class="mono" style="font-size: 11.5px">{{ fmtTime(detail.last_seen) }}</span>
            </div>
            <div v-for="([k, v], i) in extraFields(detail)" :key="k + i" class="field">
              <span class="field-label">{{ k }}</span>
              <span class="mono ellipsis" style="font-size: 11.5px" :title="String(v)">{{ v }}</span>
            </div>
          </div>
        </div>
        <div class="modal-foot">
          <button class="btn sm" @click="copy(detail.matched || detail.url)"><Icon name="copy" :size="12" />复制命中地址</button>
          <a v-if="String(detail.matched || detail.url).startsWith('http')" :href="detail.matched || detail.url"
             target="_blank" rel="noopener" class="btn sm primary">
            <Icon name="external" :size="12" />打开地址
          </a>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.facet-title {
  margin: 10px 0 4px;
  font-family: var(--mono);
  font-size: 9px;
  letter-spacing: 0.8px;
  text-transform: uppercase;
  color: var(--muted-2);
}
.facet-title:first-child { margin-top: 0; }
.facet {
  display: flex; align-items: center; justify-content: space-between; gap: 6px;
  width: 100%; height: 26px; padding: 0 6px;
  border-radius: 6px; font-size: 11.5px; color: var(--text-2); text-align: left;
}
.facet:hover { background: rgba(120, 200, 220, 0.07); }
.facet.on { background: rgba(52, 229, 200, 0.13); color: var(--cyan-ink); }
.scope-row { display: flex; flex-wrap: wrap; gap: 8px; }
.chip {
  display: inline-flex; align-items: center; height: 22px; padding: 0 8px;
  border: 1px solid var(--line); border-radius: 6px; font-size: 11px; color: var(--text-2);
}
.chip.on { border-color: rgba(52, 229, 200, 0.34); background: rgba(52, 229, 200, 0.1); color: var(--cyan-ink); }
.chip-x {
  margin-left: 4px; border: 0; background: transparent; cursor: pointer;
  color: inherit; font-size: 12px; line-height: 1; padding: 0 2px;
}
</style>
