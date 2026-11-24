<script setup>
import { computed, nextTick, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import * as echarts from 'echarts'
import Icon from '@/components/Icon.vue'
import {
  overview as fetchOverview, diff as fetchDiff, vulnStats as fetchVulnStats,
} from '@/api/endpoints'

const router = useRouter()
const data = ref(null)
const vulns = ref({ total: 0, buckets: [] })
const added = ref([])
const loading = ref(true)
const refreshedAt = ref('')
const trendEl = ref(null)
const pieEl = ref(null)
const fpEl = ref(null)
let charts = []

const PALETTE = ['#34e5c8', '#9d8cff', '#f5b544', '#5aa9ff', '#ff8fb1', '#46d68a', '#77909f']

const KIND_LABEL = {
  site: '站点', domain: '域名', ip: 'IP', service: '服务', port: '端口', cidr: 'C 段',
  email: '邮箱', leak: '泄露', vuln: '漏洞', cert: '证书', applet: '小程序', wxmp: '公众号',
  mobile: 'App', takeover: '子域接管', nuclei: 'POC 命中', api: '接口', js: 'JS 文件',
  icp: '备案', enterprise: '企业', equity: '股权', branch: '分支机构', holds: '控股企业',
  invest: '对外投资', partner: '股东', copyright: '软著', github: '代码仓库',
}
const STATUS_TEXT = {
  running: '执行中', done: '已完成', stopped: '已停止', error: '异常', pending: '排队中',
}
const STATUS_CLASS = {
  running: 'cyan', done: 'ok', stopped: '', error: 'err', pending: 'warn',
}

const kindRows = computed(() => Object.entries(data.value?.by_kind || {})
  .map(([kind, count]) => ({ kind, label: KIND_LABEL[kind] || kind, count }))
  .sort((a, b) => b.count - a.count))

const taskTotal = computed(() => Object.values(data.value?.tasks || {}).reduce((a, b) => a + b, 0))

const sevMap = computed(() => Object.fromEntries(
  (vulns.value.buckets || []).map((b) => [b.key, b.count])))

const metrics = computed(() => {
  const d = data.value
  if (!d) return []
  const rate = d.total ? Math.round((d.site / d.total) * 1000) / 10 : 0
  return [
    { key: 'total', label: '资产总量', icon: 'layers', tone: 'cyan', value: d.total,
      foot: `覆盖 ${kindRows.value.length} 种类型`, to: '/assets' },
    { key: 'site', label: '存活站点', icon: 'globe', tone: 'ok', value: d.site,
      foot: `存活占比 ${rate}%`, to: '/assets?kind=site' },
    { key: 'new', label: '24H 新增', icon: 'spark', tone: 'amber', value: d.new_day,
      foot: `近 7 日 ${Number(d.new_week || 0).toLocaleString()} 条`, to: '/assets?is_new=1' },
    { key: 'roots', label: '根域资产组', icon: 'group', tone: 'violet', value: d.roots || 0,
      foot: '按注册根域聚合', to: '/groups' },
    { key: 'vuln', label: '风险漏洞', icon: 'shield', tone: 'red', value: vulns.value.total || 0,
      foot: `严重 ${sevMap.value.critical || 0} · 高危 ${sevMap.value.high || 0}`, to: '/vulns' },
    { key: 'run', label: '执行中任务', icon: 'bolt', tone: 'cyan', value: d.running || 0,
      foot: `累计 ${taskTotal.value} 个任务`, to: '/tasks' },
  ]
})

const heroLine = computed(() => {
  const d = data.value
  if (!d) return '正在读取引擎状态…'
  if (!d.total) return '库里还没有资产。发起一次「一键收集」，从这里长出你的攻击面地图。'
  return `已入库 ${Number(d.total).toLocaleString()} 条资产，覆盖 ${Number(d.roots || 0).toLocaleString()} 个根域 · `
    + `${Number(d.site).toLocaleString()} 个站点存活 · 近 24 小时新增 ${Number(d.new_day).toLocaleString()} 条`
})

const composition = computed(() => {
  const rows = kindRows.value.filter((r) => r.count > 0)
  const head = rows.slice(0, 6)
  const rest = rows.slice(6).reduce((s, r) => s + r.count, 0)
  const out = head.map((r, i) => ({ ...r, color: PALETTE[i % PALETTE.length] }))
  if (rest > 0) out.push({ kind: 'other', label: '其他', count: rest, color: PALETTE[6] })
  const sum = out.reduce((s, r) => s + r.count, 0) || 1
  return out.map((r) => ({ ...r, pct: Math.round((r.count / sum) * 1000) / 10 }))
})

const rootRows = computed(() => {
  const rows = (data.value?.top_roots || []).slice(0, 10)
  const max = Math.max(1, ...rows.map((r) => r.count))
  return rows.map((r, i) => ({ ...r, rank: i + 1, w: Math.max(3, Math.round((r.count / max) * 100)) }))
})

const portRows = computed(() => {
  const rows = (data.value?.top_ports || []).slice(0, 16)
  const max = Math.max(1, ...rows.map((r) => r.count))
  return rows.map((r) => ({ ...r, hot: r.count / max >= 0.55 ? 'hot' : r.count / max >= 0.22 ? 'warm' : '' }))
})

async function load() {
  loading.value = true
  try {
    const [ov, df, vs] = await Promise.all([
      fetchOverview(),
      fetchDiff().catch(() => ({ items: [] })),
      fetchVulnStats().catch(() => ({ total: 0, buckets: [] })),
    ])
    data.value = ov
    vulns.value = { total: vs?.total || 0, buckets: vs?.buckets || [] }
    added.value = (df.items || []).filter((x) => x.new_count > 0).slice(0, 6)
    refreshedAt.value = new Date().toLocaleTimeString('zh-CN', { hour12: false })
    // 图表容器在数据回来后才渲染，必须等 DOM 挂载再 init
    await nextTick()
    render()
  } finally {
    loading.value = false
  }
}

function render() {
  charts.forEach((c) => c.dispose())
  charts = []
  renderTrend()
  renderPie()
  renderFingerprints()
}

function renderTrend() {
  if (!trendEl.value) return
  const c = echarts.init(trendEl.value)
  const rows = data.value?.trend || []
  const counts = rows.map((t) => t.count)
  const avg = counts.length ? counts.reduce((a, b) => a + b, 0) / counts.length : 0
  c.setOption({
    grid: { left: 38, right: 16, top: 26, bottom: 24 },
    tooltip: {
      trigger: 'axis',
      backgroundColor: 'rgba(8,17,26,.94)',
      borderColor: 'rgba(115,196,214,.24)',
      textStyle: { color: '#d9e7ef', fontSize: 11 },
      axisPointer: { type: 'shadow', shadowStyle: { color: 'rgba(52,229,200,.06)' } },
    },
    xAxis: {
      type: 'category',
      data: rows.map((t) => t.day),
      axisTick: { show: false },
      axisLine: { lineStyle: { color: 'rgba(115,196,214,.2)' } },
      axisLabel: { color: '#77909f', fontSize: 10, fontFamily: 'JetBrains Mono, monospace' },
    },
    yAxis: {
      type: 'value',
      splitLine: { lineStyle: { color: 'rgba(115,196,214,.08)' } },
      axisLabel: { color: '#77909f', fontSize: 10 },
    },
    series: [{
      type: 'bar',
      data: counts,
      barWidth: '44%',
      itemStyle: {
        borderRadius: [4, 4, 0, 0],
        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
          { offset: 0, color: 'rgba(52,229,200,.92)' },
          { offset: 1, color: 'rgba(33,184,165,.12)' },
        ]),
      },
      emphasis: { itemStyle: { color: '#5cf3dd' } },
      markLine: {
        silent: true,
        symbol: 'none',
        lineStyle: { color: 'rgba(245,181,68,.55)', type: 'dashed', width: 1 },
        label: {
          formatter: `日均 ${Math.round(avg)}`, color: '#f5b544',
          fontSize: 9.5, position: 'insideEndTop',
        },
        data: [{ yAxis: avg }],
      },
    }],
  })
  charts.push(c)
}

function renderPie() {
  if (!pieEl.value) return
  const c = echarts.init(pieEl.value)
  const rows = composition.value
  c.setOption({
    tooltip: {
      trigger: 'item',
      backgroundColor: 'rgba(8,17,26,.94)',
      borderColor: 'rgba(115,196,214,.24)',
      textStyle: { color: '#d9e7ef', fontSize: 11 },
      formatter: (p) => `${p.name}<br/><b>${Number(p.value).toLocaleString()}</b> · ${p.percent}%`,
    },
    series: [{
      type: 'pie',
      radius: ['64%', '86%'],
      center: ['50%', '50%'],
      avoidLabelOverlap: false,
      label: { show: false },
      labelLine: { show: false },
      itemStyle: { borderColor: 'rgba(9,19,28,.9)', borderWidth: 3 },
      emphasis: { scale: true, scaleSize: 4 },
      data: rows.map((r) => ({
        name: r.label, value: r.count, itemStyle: { color: r.color },
      })),
    }],
  })
  charts.push(c)
}

function renderFingerprints() {
  if (!fpEl.value) return
  const c = echarts.init(fpEl.value)
  const items = (data.value?.top_fingerprints || []).slice(0, 9)
  c.setOption({
    grid: { left: 8, right: 34, top: 8, bottom: 8, containLabel: true },
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow' },
      backgroundColor: 'rgba(8,17,26,.94)',
      borderColor: 'rgba(115,196,214,.24)',
      textStyle: { color: '#d9e7ef', fontSize: 11 },
    },
    xAxis: {
      type: 'value',
      splitLine: { lineStyle: { color: 'rgba(115,196,214,.08)' } },
      axisLabel: { color: '#77909f', fontSize: 10 },
    },
    yAxis: {
      type: 'category',
      inverse: true,
      data: items.map((i) => i.fingerprint),
      axisTick: { show: false },
      axisLine: { show: false },
      axisLabel: {
        color: '#a9bfcd', fontSize: 10.5, width: 96, overflow: 'truncate',
      },
    },
    series: [{
      type: 'bar',
      data: items.map((i) => i.count),
      barWidth: 9,
      label: {
        show: true, position: 'right', color: '#77909f',
        fontSize: 9.5, fontFamily: 'JetBrains Mono, monospace',
      },
      itemStyle: {
        borderRadius: [0, 4, 4, 0],
        color: new echarts.graphic.LinearGradient(0, 0, 1, 0, [
          { offset: 0, color: 'rgba(157,140,255,.35)' },
          { offset: 1, color: 'rgba(157,140,255,.95)' },
        ]),
      },
    }],
  })
  charts.push(c)
}

function fmtTime(ts) {
  if (!ts) return '-'
  const d = new Date(ts * 1000)
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getMonth() + 1}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

function onResize() {
  charts.forEach((c) => c.resize())
}

onMounted(() => {
  load()
  window.addEventListener('resize', onResize)
})
onBeforeUnmount(() => {
  window.removeEventListener('resize', onResize)
  charts.forEach((c) => c.dispose())
})
</script>

<template>
  <div class="stack dash">
    <!-- 态势头图：品牌 + 实时概况 + 雷达 -->
    <section class="hero">
      <div class="hero-lines" />
      <div class="hero-copy">
        <div class="eyebrow">
          <span class="live-dot" />LIVE RECON · 天鉴 · 索舆
        </div>
        <h1>全域资产<span>作战态势</span></h1>
        <p class="hero-desc">{{ heroLine }}</p>
        <div class="hero-chips">
          <span class="chip cyan"><Icon name="bolt" :size="11" />运行中 {{ data?.running || 0 }}</span>
          <span class="chip"><Icon name="spark" :size="11" />24H 新增 {{ Number(data?.new_day || 0).toLocaleString() }}</span>
          <span class="chip shield"><Icon name="shield" :size="11" />严重 {{ sevMap.critical || 0 }} · 高危 {{ sevMap.high || 0 }}</span>
          <span v-if="refreshedAt" class="chip ghost">更新于 {{ refreshedAt }}</span>
        </div>
        <div class="hero-actions">
          <button class="btn primary" @click="router.push('/oneclick')">
            <Icon name="bolt" :size="14" />发起一键收集
          </button>
          <button class="btn" @click="router.push('/assets')">
            <Icon name="search" :size="14" />资产检索
          </button>
          <button class="btn ghost" :disabled="loading" @click="load">
            <Icon name="refresh" :size="14" />刷新
          </button>
        </div>
      </div>
      <div class="radar" aria-hidden="true">
        <div class="ring r1" /><div class="ring r2" /><div class="ring r3" />
        <div class="cross x" /><div class="cross y" />
        <div class="sweep" />
        <i class="blip b1" /><i class="blip b2" /><i class="blip b3" />
        <div class="radar-core">
          <b>{{ Number(data?.roots || 0).toLocaleString() }}</b>
          <span>ROOT DOMAINS</span>
          <em>根域资产组</em>
        </div>
      </div>
    </section>

    <!-- 指标卡 -->
    <div class="kpi-row">
      <template v-if="loading && !data">
        <div v-for="i in 6" :key="i" class="skeleton" style="height: 92px" />
      </template>
      <button
        v-for="m in metrics" v-else :key="m.key"
        class="kpi" :class="`tone-${m.tone}`"
        @click="router.push(m.to)"
      >
        <span class="kpi-top">
          <span class="ico"><Icon :name="m.icon" :size="15" /></span>
          <span class="kpi-label">{{ m.label }}</span>
          <Icon name="chevron" :size="11" class="kpi-go" />
        </span>
        <span class="kpi-value">{{ Number(m.value || 0).toLocaleString() }}</span>
        <span class="kpi-foot">{{ m.foot }}</span>
      </button>
    </div>

    <template v-if="data">
      <!-- 趋势 + 构成 -->
      <div class="dash-grid">
        <div class="panel">
          <div class="panel-head">
            <span><Icon name="chart" :size="13" />资产入库趋势</span>
            <span class="head-note">
              近 7 日合计 <b class="mono">{{ Number(data.new_week || 0).toLocaleString() }}</b> 条
            </span>
          </div>
          <div ref="trendEl" class="chart" style="height: 236px" />
        </div>

        <div class="panel">
          <div class="panel-head">
            <span><Icon name="layers" :size="13" />资产构成</span>
            <router-link to="/assets" class="panel-link">全部资产<Icon name="chevron" :size="10" /></router-link>
          </div>
          <div class="donut-wrap">
            <div ref="pieEl" class="chart" style="height: 168px" />
            <div class="donut-center">
              <b class="mono">{{ Number(data.total || 0).toLocaleString() }}</b>
              <span>资产总量</span>
            </div>
          </div>
          <div class="legend">
            <div v-for="r in composition" :key="r.kind" class="legend-row">
              <i class="dot" :style="{ background: r.color }" />
              <span class="legend-name ellipsis">{{ r.label }}</span>
              <span class="legend-bar"><i :style="{ width: `${Math.max(2, r.pct)}%`, background: r.color }" /></span>
              <span class="legend-num mono">{{ Number(r.count).toLocaleString() }}</span>
              <span class="legend-pct mono">{{ r.pct }}%</span>
            </div>
            <div v-if="!composition.length" class="empty" style="padding: 12px">暂无资产</div>
          </div>
        </div>
      </div>

      <!-- 根域 + 指纹 -->
      <div class="dash-grid">
        <div class="panel">
          <div class="panel-head">
            <span><Icon name="group" :size="13" />根域资产组 TOP</span>
            <router-link to="/groups" class="panel-link">全部资产组<Icon name="chevron" :size="10" /></router-link>
          </div>
          <div class="root-list">
            <button
              v-for="r in rootRows" :key="r.root_domain" class="root-row"
              @click="router.push(`/group/${r.root_domain}`)"
            >
              <span class="root-rank mono">{{ String(r.rank).padStart(2, '0') }}</span>
              <span class="root-domain mono ellipsis">{{ r.root_domain }}</span>
              <span class="root-bar"><i :style="{ width: `${r.w}%` }" /></span>
              <span class="root-count mono">{{ Number(r.count).toLocaleString() }}</span>
            </button>
            <div v-if="!rootRows.length" class="empty">
              <Icon name="route" :size="22" /><span>还没有根域资产，先跑一轮收集</span>
            </div>
          </div>
        </div>

        <div class="panel">
          <div class="panel-head">
            <span><Icon name="tags" :size="13" />指纹分布 TOP</span>
            <span class="mono muted" style="font-size: 10px">fingerprint</span>
          </div>
          <div ref="fpEl" class="chart" style="height: 294px" />
        </div>
      </div>

      <!-- 任务 + 右侧信息 -->
      <div class="dash-grid">
        <div class="panel">
          <div class="panel-head">
            <span><Icon name="tasks" :size="13" />最近任务</span>
            <router-link to="/tasks" class="panel-link">全部任务<Icon name="chevron" :size="10" /></router-link>
          </div>
          <div class="table-wrap">
            <table class="table">
              <thead><tr><th>任务</th><th>状态</th><th style="width: 132px">进度</th><th style="width: 92px">时间</th></tr></thead>
              <tbody>
                <tr
                  v-for="t in data.recent_tasks || []" :key="t.id"
                  style="cursor: pointer" @click="router.push(`/tasks/${t.id}`)"
                >
                  <td class="ellipsis" style="max-width: 320px">{{ t.name }}</td>
                  <td>
                    <span class="tag" :class="STATUS_CLASS[t.status]">
                      {{ STATUS_TEXT[t.status] || t.status }}
                    </span>
                  </td>
                  <td>
                    <div class="progress"><i :style="{ width: (t.progress || 0) + '%' }" /></div>
                    <span class="mono muted" style="font-size: 9.5px">{{ t.progress || 0 }}%</span>
                  </td>
                  <td class="mono muted">{{ fmtTime(t.created_at) }}</td>
                </tr>
                <tr v-if="!(data.recent_tasks || []).length">
                  <td colspan="4"><div class="empty">还没有任务，点上方「发起一键收集」开始</div></td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <div class="side-stack">
          <div class="panel">
            <div class="panel-head">
              <span><Icon name="server" :size="13" />端口热度</span>
              <router-link to="/assets?kind=port" class="panel-link">端口资产<Icon name="chevron" :size="10" /></router-link>
            </div>
            <div class="panel-body port-cloud">
              <span
                v-for="p in portRows" :key="p.port"
                class="port-chip" :class="p.hot"
              >
                <i class="mono">:{{ p.port }}</i><b class="mono">{{ p.count }}</b>
              </span>
              <span v-if="!portRows.length" class="muted" style="font-size: 11.5px">暂无端口数据</span>
            </div>
          </div>

          <div class="panel">
            <div class="panel-head">
              <span><Icon name="flow" :size="13" />根域新增</span>
              <router-link to="/schedules" class="panel-link">周期监控<Icon name="chevron" :size="10" /></router-link>
            </div>
            <div class="panel-body">
              <div v-if="!added.length" class="empty" style="padding: 18px 8px">
                <Icon name="route" :size="20" />
                <span>还没有变更快照。把同一目标排成周期任务，每轮会自动比对出新增资产。</span>
              </div>
              <div
                v-for="a in added" :key="a.root_domain"
                class="flex gap-8" style="padding: 6px 0; border-bottom: 1px solid var(--line-soft)"
              >
                <Icon name="target" :size="12" class="muted" />
                <router-link :to="`/group/${a.root_domain}`" class="mono flex-1 ellipsis">{{ a.root_domain }}</router-link>
                <span class="tag warn">+{{ a.new_count }}</span>
                <span class="mono muted" style="font-size: 10.5px">{{ fmtTime(a.created_at) }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </template>
  </div>
</template>

<style scoped>
.dash { gap: 13px; }

/* ── 态势头图 ─────────────────────────────────────────────── */

.hero {
  position: relative;
  display: flex; align-items: center; gap: 20px;
  overflow: hidden;
  padding: 22px 24px;
  border: 1px solid var(--line-strong);
  border-radius: 14px;
  background:
    radial-gradient(560px 260px at 8% 0%, rgba(52, 229, 200, 0.16), transparent 68%),
    radial-gradient(460px 300px at 92% 110%, rgba(157, 140, 255, 0.12), transparent 66%),
    linear-gradient(120deg, rgba(12, 26, 36, 0.92), rgba(7, 14, 21, 0.86));
  box-shadow: 0 18px 50px rgba(0, 0, 0, 0.35);
}
.hero-lines {
  position: absolute; inset: 0; pointer-events: none;
  background-image:
    linear-gradient(rgba(52, 229, 200, 0.045) 1px, transparent 1px),
    linear-gradient(90deg, rgba(52, 229, 200, 0.045) 1px, transparent 1px);
  background-size: 34px 34px;
  -webkit-mask-image: radial-gradient(90% 120% at 72% 40%, #000 10%, transparent 74%);
  mask-image: radial-gradient(90% 120% at 72% 40%, #000 10%, transparent 74%);
}
.hero-copy { position: relative; z-index: 2; flex: 1 1 auto; min-width: 0; }

.eyebrow {
  display: inline-flex; align-items: center; gap: 7px;
  font-family: var(--mono); font-size: 9.5px; letter-spacing: 1.7px;
  color: var(--cyan-2); text-transform: uppercase;
}
.live-dot {
  width: 6px; height: 6px; border-radius: 50%; background: var(--cyan);
  box-shadow: 0 0 9px var(--cyan);
  animation: breathe 2.4s ease-in-out infinite;
}
@keyframes breathe { 50% { opacity: 0.35; } }

.hero h1 {
  margin: 9px 0 7px;
  font-size: 27px; font-weight: 650; line-height: 1.2;
  letter-spacing: 0.4px; color: #eafaff;
}
.hero h1 span {
  margin-left: 8px;
  background: linear-gradient(96deg, #34e5c8, #7fd8ff 58%, #b9b0ff);
  -webkit-background-clip: text; background-clip: text;
  -webkit-text-fill-color: transparent; color: transparent;
}
.hero-desc { margin: 0 0 13px; max-width: 640px; font-size: 12px; color: var(--text-2); }

.hero-chips { display: flex; flex-wrap: wrap; gap: 7px; margin-bottom: 15px; }
.chip {
  display: inline-flex; align-items: center; gap: 5px;
  height: 22px; padding: 0 9px; border-radius: 7px;
  border: 1px solid var(--line); background: rgba(6, 12, 18, 0.5);
  font-size: 11px; color: var(--text-2); white-space: nowrap;
}
.chip svg { color: var(--cyan-2); }
.chip.cyan { border-color: rgba(52, 229, 200, 0.3); color: var(--cyan-ink); background: rgba(52, 229, 200, 0.08); }
.chip.shield { border-color: rgba(255, 100, 112, 0.28); color: var(--red-ink); background: rgba(255, 100, 112, 0.07); }
.chip.shield svg { color: var(--red); }
.chip.ghost { border-style: dashed; color: var(--muted); }

.hero-actions { display: flex; flex-wrap: wrap; gap: 8px; }

/* 雷达 */
.radar {
  position: relative; z-index: 2;
  flex: 0 0 auto; width: 194px; height: 194px; margin-right: 6px;
  display: grid; place-items: center;
}
.radar::before {
  content: ""; position: absolute; inset: -6%;
  border-radius: 50%;
  background: radial-gradient(circle, rgba(52, 229, 200, 0.14), transparent 66%);
}
.ring { position: absolute; border-radius: 50%; border: 1px solid rgba(52, 229, 200, 0.18); }
.ring.r1 { inset: 0; }
.ring.r2 { inset: 16%; border-color: rgba(52, 229, 200, 0.13); }
.ring.r3 { inset: 33%; border-color: rgba(52, 229, 200, 0.1); }
.cross { position: absolute; background: rgba(52, 229, 200, 0.1); }
.cross.x { width: 100%; height: 1px; }
.cross.y { width: 1px; height: 100%; }
.sweep {
  position: absolute; inset: 0; border-radius: 50%;
  background: conic-gradient(from 0deg, rgba(52, 229, 200, 0.5), rgba(52, 229, 200, 0.02) 24%, transparent 40%);
  -webkit-mask-image: radial-gradient(circle, transparent 14%, #000 15%);
  mask-image: radial-gradient(circle, transparent 14%, #000 15%);
  animation: spin 6s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }
.blip {
  position: absolute; width: 5px; height: 5px; border-radius: 50%;
  background: var(--cyan); box-shadow: 0 0 10px var(--cyan);
  animation: blip 3.2s ease-in-out infinite;
}
.blip.b1 { top: 26%; left: 64%; }
.blip.b2 { top: 62%; left: 24%; animation-delay: 0.9s; background: var(--violet); box-shadow: 0 0 10px var(--violet); }
.blip.b3 { top: 72%; left: 68%; animation-delay: 1.8s; }
@keyframes blip { 0%, 100% { opacity: 0.25; } 45% { opacity: 1; } }

.radar-core {
  position: relative; z-index: 3;
  display: flex; flex-direction: column; align-items: center; gap: 1px;
  padding: 10px 12px; border-radius: 12px;
  background: rgba(6, 12, 18, 0.62);
  border: 1px solid rgba(52, 229, 200, 0.22);
  backdrop-filter: blur(5px);
}
.radar-core b { font-family: var(--mono); font-size: 23px; font-weight: 600; line-height: 1.1; color: #eafaff; }
.radar-core span { font-family: var(--mono); font-size: 8px; letter-spacing: 1.6px; color: var(--cyan-2); }
.radar-core em { font-style: normal; font-size: 10px; color: var(--muted); }
@media (prefers-reduced-motion: reduce) {
  .sweep, .blip, .live-dot { animation: none; }
}

/* ── 指标卡 ───────────────────────────────────────────────── */

.kpi-row {
  display: grid;
  grid-template-columns: repeat(6, minmax(0, 1fr));
  gap: 10px;
}
@media (max-width: 1440px) {
  .kpi-row { grid-template-columns: repeat(3, minmax(0, 1fr)); }
}
.kpi {
  position: relative; overflow: hidden;
  display: flex; flex-direction: column; align-items: flex-start;
  padding: 11px 13px 10px;
  border: 1px solid var(--line); border-radius: 11px;
  background: linear-gradient(160deg, rgba(14, 27, 38, 0.8), rgba(8, 16, 24, 0.62));
  text-align: left;
  transition: border-color 0.16s, transform 0.16s, background 0.16s;
}
.kpi::after {
  content: ""; position: absolute; left: 0; right: 0; top: 0; height: 1px;
  background: linear-gradient(90deg, transparent, currentColor, transparent);
  opacity: 0.28;
}
.kpi:hover { border-color: var(--line-strong); transform: translateY(-1px); }
.kpi-top { display: flex; align-items: center; gap: 7px; width: 100%; }
.ico {
  display: grid; place-items: center;
  width: 26px; height: 26px; border-radius: 8px;
  background: rgba(120, 200, 220, 0.07);
}
.kpi-label { font-size: 11px; color: var(--muted); letter-spacing: 0.3px; }
.kpi-go { margin-left: auto; color: var(--muted-2); opacity: 0; transition: opacity 0.16s; }
.kpi:hover .kpi-go { opacity: 1; }
.kpi-value {
  margin-top: 6px;
  font-family: var(--mono); font-size: 25px; font-weight: 600;
  line-height: 1.15; color: #eafaff; letter-spacing: -0.4px;
}
.kpi-foot { margin-top: 1px; font-size: 10.5px; color: var(--muted); }

.kpi.tone-cyan { color: var(--cyan); }
.kpi.tone-cyan .ico { color: var(--cyan); background: rgba(52, 229, 200, 0.1); box-shadow: inset 0 0 0 1px rgba(52, 229, 200, 0.2); }
.kpi.tone-ok { color: #46d68a; }
.kpi.tone-ok .ico { color: #46d68a; background: rgba(70, 214, 138, 0.1); box-shadow: inset 0 0 0 1px rgba(70, 214, 138, 0.2); }
.kpi.tone-amber { color: var(--amber); }
.kpi.tone-amber .ico { color: var(--amber); background: rgba(245, 181, 68, 0.1); box-shadow: inset 0 0 0 1px rgba(245, 181, 68, 0.2); }
.kpi.tone-violet { color: var(--violet); }
.kpi.tone-violet .ico { color: var(--violet); background: rgba(157, 140, 255, 0.1); box-shadow: inset 0 0 0 1px rgba(157, 140, 255, 0.2); }
.kpi.tone-red { color: var(--red); }
.kpi.tone-red .ico { color: var(--red); background: rgba(255, 100, 112, 0.1); box-shadow: inset 0 0 0 1px rgba(255, 100, 112, 0.2); }

/* ── 面板栅格 ─────────────────────────────────────────────── */

.dash-grid {
  display: grid;
  grid-template-columns: minmax(0, 2fr) minmax(0, 1fr);
  gap: 12px;
}
.dash-grid > * { min-width: 0; }
.chart { width: 100%; }
.head-note { font-size: 10.5px; color: var(--muted); }
.head-note b { color: var(--cyan-ink); font-weight: 600; }

.donut-wrap { position: relative; padding: 8px 10px 0; }
.donut-center {
  position: absolute; inset: 8px 10px 0;
  display: flex; flex-direction: column; align-items: center; justify-content: center;
  pointer-events: none;
}
.donut-center b { font-size: 20px; font-weight: 600; color: #eafaff; line-height: 1.1; }
.donut-center span { font-size: 9.5px; color: var(--muted); letter-spacing: 0.5px; }

.legend { padding: 4px 12px 12px; display: flex; flex-direction: column; gap: 5px; }
.legend-row { display: grid; grid-template-columns: 8px minmax(46px, 1fr) minmax(40px, 1.1fr) 46px 42px; align-items: center; gap: 7px; }
.legend-row .dot { width: 6px; height: 6px; border-radius: 2px; }
.legend-name { font-size: 11px; color: var(--text-2); }
.legend-bar { height: 3px; border-radius: 2px; background: rgba(120, 200, 220, 0.08); overflow: hidden; }
.legend-bar i { display: block; height: 100%; border-radius: 2px; opacity: 0.75; }
.legend-num { font-size: 10.5px; color: var(--text-2); text-align: right; }
.legend-pct { font-size: 10px; color: var(--muted-2); text-align: right; }

/* 根域条 */
.root-list { padding: 7px 9px 10px; display: flex; flex-direction: column; gap: 2px; }
.root-row {
  display: grid;
  grid-template-columns: 24px minmax(120px, 1.15fr) minmax(60px, 1fr) 56px;
  align-items: center; gap: 9px;
  padding: 5px 6px; border-radius: 7px;
  text-align: left;
  transition: background 0.14s;
}
.root-row:hover { background: rgba(120, 200, 220, 0.05); }
.root-rank { font-size: 10px; color: var(--muted-2); }
.root-domain { font-size: 11.5px; color: var(--text); }
.root-row:hover .root-domain { color: var(--cyan-ink); }
.root-bar { height: 5px; border-radius: 3px; background: rgba(120, 200, 220, 0.07); overflow: hidden; }
.root-bar i {
  display: block; height: 100%; border-radius: 3px;
  background: linear-gradient(90deg, rgba(33, 184, 165, 0.7), var(--cyan));
  box-shadow: 0 0 10px rgba(52, 229, 200, 0.25);
}
.root-count { font-size: 11px; color: var(--text-2); text-align: right; }

/* 端口云 */
.port-cloud { display: flex; flex-wrap: wrap; gap: 6px; }
.port-chip {
  display: inline-flex; align-items: center; gap: 6px;
  height: 23px; padding: 0 8px; border-radius: 7px;
  border: 1px solid var(--line-soft);
  background: rgba(120, 200, 220, 0.04);
  font-size: 10.5px; color: var(--muted);
}
.port-chip i { font-style: normal; color: var(--text-2); }
.port-chip b { font-size: 10.5px; color: var(--muted-2); font-weight: 600; }
.port-chip.warm { border-color: rgba(52, 229, 200, 0.2); background: rgba(52, 229, 200, 0.06); }
.port-chip.warm b { color: var(--cyan-2); }
.port-chip.hot {
  border-color: rgba(52, 229, 200, 0.4);
  background: rgba(52, 229, 200, 0.12);
  color: var(--cyan-ink);
  box-shadow: 0 0 14px rgba(52, 229, 200, 0.08) inset;
}
.port-chip.hot i { color: var(--cyan-ink); }
.port-chip.hot b { color: var(--cyan); }

.side-stack { display: flex; flex-direction: column; gap: 12px; min-width: 0; }

/* ── 响应式 ───────────────────────────────────────────────── */

@media (max-width: 1240px) {
  .dash-grid { grid-template-columns: minmax(0, 1fr); }
  .side-stack { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); }
}
@media (max-width: 820px) {
  .hero { padding: 18px; }
  .radar { display: none; }
  .hero h1 { font-size: 22px; }
  .kpi-row { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .legend-row { grid-template-columns: 8px minmax(40px, 1fr) 46px 40px; }
  .legend-bar { display: none; }
}
</style>
