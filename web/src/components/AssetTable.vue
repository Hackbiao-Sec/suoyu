<script setup>
import { computed } from 'vue'
import Icon from '@/components/Icon.vue'

// 资产明细表：总览和分表共用一份，列随当前这批数据自适应。
// 主体类资产（子公司/股东/ICP/软著）没有状态码、端口，硬摆一排 Web 列就是「一堆数字看不出是什么」。
const props = defineProps({
  items: { type: Array, default: () => [] },
  // 当前分表的 kinds：非空时说明这张表就是主体类，不再看 Web 列
  sheetKinds: { type: Array, default: () => [] },
  kindLabel: { type: Object, default: () => ({}) },
  // 来源类型中文名（后端 SOURCE_LABEL）；没给就显示原始键
  sourceLabels: { type: Object, default: () => ({}) },
  loading: { type: Boolean, default: false },
  emptyText: { type: String, default: '没有匹配的资产，换个关键字或清掉分面' },
})
const emit = defineEmits(['detail'])

const k = (key) => props.kindLabel[key] || key || '-'

const WEB_KINDS = new Set(['site', 'domain', 'api', 'service', 'port', 'ip', 'sibling', 'url', 'js',
  'leak', 'leakfile', 'git', 'component', 'subdomain', 'netblock', 'cidr', 'takeover', 'bucket'])
const webShare = computed(() => {
  if (!props.items.length) return true
  return props.items.filter((a) => WEB_KINDS.has(a.kind)).length / props.items.length >= 0.4
})
const showWeb = computed(() => webShare.value && !props.sheetKinds.length)

const SKIP_EXTRA = new Set(['url', 'host', 'ip', 'port', 'title', 'kind', 'task_id', 'source',
  'content', 'raw', 'html', 'body'])
const FIELD_LABEL = {
  name: '名称', title: '标题', legal: '法人', legal_person: '法人', status: '状态',
  reg_capital: '注册资本', ratio: '比例', percent: '比例', invest_ratio: '投资比例',
  hold_ratio: '持股比例', share_ratio: '比例', level: '层级', pid: 'PID', reg_no: '登记号',
  icp: '备案号', company: '公司', website: '网址', amount: '认缴金额', city: '城市',
  edu: '学历', supplier: '供应商', app_id: 'AppID', bundle_id: '包名', version: '版本',
  category: '分类', link: '链接', address: '地址', phone: '电话', email: '邮箱',
  code: '信用代码', start_date: '成立日期', market: '市场', author: '作者', app: '应用',
  protocol: '协议', isp: 'ISP', os: 'OS', country: '国家', province: '省份', city_name: '城市',
  parent: '上级', pid_name: '上级', note: '备注', remark: '备注', industry: '行业',
  relation: '关系', ratio_text: '比例',
}
// 名称/标题已经是第一列，别在动态列里再来一遍
const NAME_KEYS = new Set(['name', 'title'])
// 一张分表里每行都有的字段才提成列，避免整列空白
const dynCols = computed(() => {
  if (showWeb.value) return []
  const rows = props.items.filter((a) => !WEB_KINDS.has(a.kind))
  if (!rows.length) return []
  const hits = {}
  for (const r of rows) {
    const ex = r.extra && typeof r.extra === 'object' ? r.extra : {}
    for (const [key, val] of Object.entries(ex)) {
      if (SKIP_EXTRA.has(key) || NAME_KEYS.has(key) || val === null || val === undefined || val === '') continue
      if (typeof val === 'object') continue
      if (String(val).length > 60) continue
      hits[key] = (hits[key] || 0) + 1
    }
  }
  const floor = Math.max(2, Math.round(rows.length * 0.3))
  return Object.entries(hits)
    .filter(([, n]) => n >= floor)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 4)
    .map(([key]) => ({ key, label: FIELD_LABEL[key] || key }))
})

function exVal(a, key) {
  const ex = a.extra && typeof a.extra === 'object' ? a.extra : {}
  const v = ex[key]
  if (v === null || v === undefined || v === '') return '-'
  // 同一字段在不同行可能是对象，别在单元格里印 [object Object]
  return typeof v === 'object' ? '-' : String(v)
}
// 泄露线索值什么：IP / 邮箱 / 手机号 / JS 片段都可能是被扫到的内容，
// 地址列只放这个值，出处统一在「来源」列，别把 leak:ip:1.2.3.4 当网站地址
function leakValue(a) {
  const ex = a.extra && typeof a.extra === 'object' ? a.extra : {}
  if (ex.value) return String(ex.value)
  if (ex.url) return String(ex.url)
  const m = String(a.url || '').match(/^leak(?:file)?:[a-z_]+:(.*)$/i)
  return m ? m[1] : String(a.url || '')
}
// 内部存储前缀（domain:/api:/port:…）是入库约定，不该印在地址列
const URL_PREFIX = /^(domain|api|service|port|sibling|vhost|netblock|cidr|subdomain|url):/i
const stripPrefix = (s) => String(s || '').replace(URL_PREFIX, '')
// 主体类资产没有站点标题：优先取名称，其次才是标题
function rowName(a) {
  // 裸 IP 这类泄露线索：地址列直接给出被泄露的值，出处放到「来源」列，
  // 否则一行 leak:ip:1.2.3.4 既看不出是什么、也看不出哪来的
  if (a.kind === 'leak' || a.kind === 'leakfile') return leakValue(a) || a.title || a.url
  if (WEB_KINDS.has(a.kind)) return stripPrefix(a.title || a.url)
  const ex = a.extra && typeof a.extra === 'object' ? a.extra : {}
  return ex.name || ex.title || a.title || stripPrefix(a.url)
}
// 来源：类型 + 具体出处（站点 URL / 小程序 AppID / JS 地址），鼠标悬停看全
const showSrc = computed(() => props.items.some((a) => a.source_type))
const srcLabel = (a) => props.sourceLabels[a.source_type] || a.source_type || '-'
// 小程序 / APP 这类出处没有可点的网址：先露出小程序或应用的名字，退一步才用 AppID 尾巴；
// 站点爬虫 / JS 这类出处是网址，露出主机名，一眼看得出是从哪个站扫到的
function srcShort(a) {
  const origin = String(a.source_url || '').trim()
  const ex = a.extra && typeof a.extra === 'object' ? a.extra : {}
  const appName = ex.applet || ex.app || ex.app_name
  if (appName && /^(applet|app|mobile)$/i.test(String(a.source_type || ''))) {
    const s = String(appName)
    return s.length > 10 ? `${s.slice(0, 10)}…` : s
  }
  if (!origin) return ''
  if (/^https?:/i.test(origin)) {
    try {
      const host = new URL(origin).hostname
      if (!host) return ''
      return host.length > 22 ? `${host.slice(0, 22)}…` : host
    } catch (e) { return '' }
  }
  const tail = origin.split(':').filter(Boolean).pop() || ''
  if (!tail || tail === String(a.source_type || '')) return ''
  return tail.length > 9 ? `${tail.slice(0, 9)}…` : tail
}
function srcTitle(a) {
  const label = srcLabel(a)
  const origin = String(a.source_url || '').trim()
  const ex = a.extra && typeof a.extra === 'object' ? a.extra : {}
  // 小程序 / APP 真实名字和 AppID 不是一回事，悬停时先把名字写出来再给出处
  const appName = String(ex.applet || ex.app || ex.app_name || '')
  const nick = appName && appName !== String(ex.appid || '') ? `${appName} · ` : ''
  return origin ? `${label} · ${nick}出处 ${origin}` : `${label}${nick ? ' · ' + nick.slice(0, -3) : ''}`
}
function fmtTime(ts) {
  if (!ts) return '-'
  const d = new Date(ts * 1000)
  const p = (n) => String(n).padStart(2, '0')
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}
// 存活：后端 live_state 给 alive / alive_text，站点看码、域名看解析、端口看实测
const ALIVE_CLS = { alive: 'ok', open: 'ok', dns: 'cyan', auth: 'warn', space: 'info', bad: 'err' }
const aliveCls = (a) => ALIVE_CLS[a.alive] || ''
const aliveText = (a) => a.alive_text || (a.status_code ? String(a.status_code) : '未探测')
const colCount = computed(() =>
  4 + dynCols.value.length + (showWeb.value ? 6 : 0) + (showSrc.value ? 1 : 0))
</script>

<template>
  <div class="table-wrap">
    <table class="table">
      <thead>
        <tr>
          <th style="width: 82px">类型</th>
          <th>{{ showWeb ? '地址' : '名称' }}</th>
          <th v-if="showSrc" style="width: 152px">来源</th>
          <th v-for="c in dynCols" :key="c.key">{{ c.label }}</th>
          <template v-if="showWeb">
            <th style="width: 92px">存活</th>
            <th style="width: 118px">IP</th>
            <th style="width: 56px">端口</th>
            <th style="width: 150px">指纹</th>
            <th style="width: 90px">CDN</th>
          </template>
          <th style="width: 92px">最近</th>
          <th style="width: 44px"></th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="a in items" :key="a.id">
          <td><span class="tag">{{ k(a.kind) }}</span></td>
          <td class="mono cell-url" :title="[rowName(a), a.title, a.url].filter(Boolean).join(' · ')">
            <a v-if="String(rowName(a)).startsWith('http')" :href="rowName(a)" target="_blank" rel="noopener">{{ rowName(a) }}</a>
            <span v-else>{{ rowName(a) }}</span>
            <span v-if="a.is_new" class="tag warn" style="margin-left: 6px">NEW</span>
          </td>
          <td v-if="showSrc" class="ellipsis" style="max-width: 168px">
            <a v-if="String(a.source_url || '').startsWith('http')" :href="a.source_url" target="_blank"
               rel="noopener" class="tag src" :title="srcTitle(a)">{{ srcLabel(a) }}<template v-if="srcShort(a)"> · {{ srcShort(a) }}</template></a>
            <span v-else-if="a.source_type" class="tag src" :title="srcTitle(a)">{{ srcLabel(a) }}<template v-if="srcShort(a)"> · {{ srcShort(a) }}</template></span>
            <span v-else class="muted">-</span>
          </td>
          <td v-for="c in dynCols" :key="c.key" class="ellipsis" style="max-width: 180px" :title="exVal(a, c.key)">
            {{ exVal(a, c.key) }}
          </td>
          <template v-if="showWeb">
            <td>
              <span class="tag" :class="aliveCls(a)" :title="'状态码 ' + (a.status_code || '无')">{{ aliveText(a) }}</span>
            </td>
            <td class="mono">{{ a.ip || '-' }}</td>
            <td class="mono">{{ a.port || '-' }}</td>
            <td class="ellipsis" style="max-width: 150px">{{ a.fingerprint }}</td>
            <td class="ellipsis" style="max-width: 90px">{{ a.cdn }}</td>
          </template>
          <td class="mono muted">{{ fmtTime(a.last_seen) }}</td>
          <td style="text-align: right">
            <button class="btn xs" @click="emit('detail', a)"><Icon name="eye" :size="11" /></button>
          </td>
        </tr>
        <tr v-if="!items.length && !loading">
          <td :colspan="colCount">
            <div class="empty"><Icon name="search" :size="22" />{{ emptyText }}</div>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>
