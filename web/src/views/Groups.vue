<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import PageHead from '@/components/PageHead.vue'
import Icon from '@/components/Icon.vue'
import { groups, diff as fetchDiff, listAssets } from '@/api/endpoints'

const router = useRouter()
const keyword = ref('')
const mode = ref('root')
const items = ref([])
const changes = ref({})
const loading = ref(false)

const assets = ref([])
const assetsTotal = ref(0)

const MODES = [
  { k: 'root', label: '资产组', icon: 'group' },
  { k: 'asset', label: '资产检索', icon: 'search' },
  { k: 'task', label: '任务', icon: 'tasks' },
]

const sums = computed(() => items.value.reduce((s, i) => {
  s.total += i.cnt || i.total || 0
  s.web += i.web || 0
  s.applet += i.applet || 0
  s.app += i.app || 0
  return s
}, { total: 0, web: 0, applet: 0, app: 0 }))

// 资产分布：把最大的几组直接画成条，入口不用翻表也能看出这轮的资产堆在哪
const topRoots = computed(() => {
  const list = [...items.value].sort((a, b) => (b.cnt || 0) - (a.cnt || 0)).slice(0, 12)
  const max = Math.max(1, ...list.map((g) => g.cnt || 0))
  return list.map((g) => ({ ...g, pct: Math.round(((g.cnt || 0) / max) * 100) }))
})

const assetKinds = computed(() => {
  const map = {}
  for (const a of assets.value) map[a.kind] = (map[a.kind] || 0) + 1
  return Object.entries(map).sort((a, b) => b[1] - a[1]).slice(0, 10)
})

async function loadGroups() {
  loading.value = true
  try {
    const res = await groups({
      keyword: keyword.value.trim() || undefined,
      limit: 300,
      by: mode.value === 'task' ? 'task' : undefined,
    })
    items.value = res.items || []
    if (mode.value === 'root') {
      const df = await fetchDiff().catch(() => ({ items: [] }))
      changes.value = {}
      for (const d of df.items || []) changes.value[d.root_domain] = d
    } else {
      changes.value = {}
    }
  } finally {
    loading.value = false
  }
}

// 资产检索：关键词直接打到资产库，结果里带根域，一眼知道它属于哪个组
async function searchAssets() {
  loading.value = true
  try {
    const res = await listAssets({ keyword: keyword.value.trim() || undefined, limit: 300 })
    assets.value = res.items || []
    assetsTotal.value = res.total || assets.value.length
  } finally {
    loading.value = false
  }
}

function reload() {
  return mode.value === 'asset' ? searchAssets() : loadGroups()
}

function switchMode(m) {
  if (mode.value === m) return
  mode.value = m
  reload()
}

function openTask(g) {
  router.push({ path: `/tasks/${g.task_id}` })
}

function openGroup(root) {
  router.push({ path: `/group/${root}` })
}

function openAssets(g, surface) {
  const q = {}
  if (g.task_id) q.task = g.task_id
  if (surface) q.surface = surface
  router.push({ path: '/assets', query: q })
}

function openRootAssets(root, surface) {
  const q = { root }
  if (surface) q.surface = surface
  router.push({ path: '/assets', query: q })
}

function fmtTime(ts) {
  if (!ts) return '-'
  const d = new Date(ts * 1000)
  const p = (n) => String(n).padStart(2, '0')
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

const STATUS_LABEL = { done: '完成', running: '进行中', stopped: '已停', error: '失败', pending: '待跑' }
const KIND_LABEL = {
  site: '站点', domain: '域名', ip: 'IP', service: '服务', port: '端口', cidr: 'C 段', email: '邮箱',
  leak: '泄露', vuln: '漏洞', takeover: '子域接管', icp: '备案', enterprise: '企业', equity: '股权',
  branch: '分支机构', holds: '控股企业', invest: '对外投资', partner: '股东', copyright: '软著',
  applet: '小程序', wxmp: '公众号', mobile: 'APP', nuclei: 'POC 命中',
}

onMounted(loadGroups)
</script>

<template>
  <div class="stack">
    <PageHead
      title="资产组"
      desc="一个页面看全：按根域看资产簇、直接搜具体资产、或者按任务看谁收进来多少"
    >
      <template #actions>
        <div class="seg">
          <button v-for="m in MODES" :key="m.k" :class="{ on: mode === m.k }" @click="switchMode(m.k)">
            {{ m.label }}
          </button>
        </div>
        <button class="btn sm" @click="reload"><Icon name="refresh" :size="13" />刷新</button>
      </template>
    </PageHead>

    <div class="search-row">
      <div class="search-box">
        <Icon name="search" :size="15" />
        <input
          v-model="keyword"
          class="search-input"
          :placeholder="mode === 'root' ? '搜根域 / 品牌 / 域名，回车查询' : mode === 'asset' ? '搜域名 / 标题 / IP / 指纹，回车查询' : '搜任务名 / 目标 / 任务 ID，回车查询'"
          @keyup.enter="reload"
        />
        <button v-if="keyword" class="search-clear" @click="keyword = ''; reload()"><Icon name="close" :size="12" /></button>
      </div>
      <button class="btn primary sm" @click="reload"><Icon name="search" :size="13" />查询</button>
    </div>

    <template v-if="mode !== 'asset'">
      <div class="metric-row">
        <div class="metric">
          <span class="metric-label">{{ mode === 'root' ? 'GROUPS' : 'TASKS' }}</span>
          <span class="metric-value">{{ items.length }}</span>
          <span class="metric-foot">{{ mode === 'root' ? '根域资产组' : '有资产的任务' }}</span>
        </div>
        <div class="metric">
          <span class="metric-label">ASSETS</span>
          <span class="metric-value">{{ sums.total.toLocaleString() }}</span>
          <span class="metric-foot">组内资产合计</span>
        </div>
        <div class="metric">
          <span class="metric-label">WEB</span>
          <span class="metric-value">{{ sums.web.toLocaleString() }}</span>
          <span class="metric-foot">域名 / 站点 / 服务</span>
        </div>
        <div class="metric">
          <span class="metric-label">小程序 / APP</span>
          <span class="metric-value">{{ sums.applet }} / {{ sums.app }}</span>
          <span class="metric-foot">移动端资产</span>
        </div>
      </div>

      <div v-if="mode === 'root' && topRoots.length" class="panel">
        <div class="panel-head">
          <span><Icon name="chart" :size="13" />资产分布 TOP {{ topRoots.length }}</span>
          <span class="mono muted">点条直接进组</span>
        </div>
        <div class="panel-body dist">
          <button v-for="g in topRoots" :key="g.root_domain" class="dist-row" @click="openGroup(g.root_domain)">
            <span class="dist-name mono">{{ g.root_domain }}</span>
            <span class="dist-bar"><span class="dist-fill" :style="{ width: g.pct + '%' }" /></span>
            <span class="dist-num mono">{{ g.cnt }}</span>
            <span class="dist-sub mono muted">站点 {{ g.sites }} · IP {{ g.ips }}</span>
          </button>
        </div>
      </div>
    </template>

    <template v-else>
      <div class="metric-row">
        <div class="metric">
          <span class="metric-label">MATCH</span>
          <span class="metric-value">{{ assetsTotal.toLocaleString() }}</span>
          <span class="metric-foot">命中资产总数</span>
        </div>
        <div class="metric">
          <span class="metric-label">SHOWN</span>
          <span class="metric-value">{{ assets.length }}</span>
          <span class="metric-foot">当前加载条数</span>
        </div>
        <div class="metric">
          <span class="metric-label">TYPES</span>
          <span class="metric-value">{{ assetKinds.length }}</span>
          <span class="metric-foot">涉及资产类型</span>
        </div>
        <div class="metric">
          <span class="metric-label">NEW</span>
          <span class="metric-value">{{ assets.filter((a) => a.is_new).length }}</span>
          <span class="metric-foot">其中最近新增</span>
        </div>
      </div>
    </template>

    <div v-if="mode === 'asset'" class="panel">
      <div class="panel-head">
        <span><Icon name="search" :size="13" />资产检索结果</span>
        <span class="row" style="gap: 6px">
          <span v-for="[k, v] in assetKinds" :key="k" class="tag">{{ KIND_LABEL[k] || k }} {{ v }}</span>
        </span>
      </div>
      <div class="table-wrap">
        <table class="table">
          <thead>
            <tr><th>所属组</th><th>类型</th><th>地址</th><th>标题</th><th>状态</th><th>IP</th><th>端口</th><th>指纹</th><th>最近</th></tr>
          </thead>
          <tbody>
            <tr v-for="a in assets" :key="a.id">
              <td class="mono">
                <a v-if="a.root_domain" class="num-link" @click="openGroup(a.root_domain)">{{ a.root_domain }}</a>
                <span v-else class="muted">-</span>
              </td>
              <td><span class="tag">{{ KIND_LABEL[a.kind] || a.kind }}</span></td>
              <td class="mono cell-url" :title="a.url">
                <a :href="a.url?.startsWith('http') ? a.url : undefined" target="_blank" rel="noopener">{{ a.url }}</a>
                <span v-if="a.is_new" class="tag warn" style="margin-left: 6px">NEW</span>
              </td>
              <td class="ellipsis" style="max-width: 220px" :title="a.title">{{ a.title }}</td>
              <td class="mono">{{ a.status_code || '-' }}</td>
              <td class="mono">{{ a.ip }}</td>
              <td class="mono">{{ a.port || '-' }}</td>
              <td class="ellipsis" style="max-width: 180px">{{ a.fingerprint }}</td>
              <td class="mono muted">{{ fmtTime(a.last_seen) }}</td>
            </tr>
            <tr v-if="!assets.length && !loading">
              <td colspan="9"><div class="empty"><Icon name="search" :size="22" />没有命中的资产，换个关键词试试</div></td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <div v-else class="panel">
      <div class="panel-head">
        <span>
          <Icon :name="mode === 'root' ? 'group' : 'tasks'" :size="13" />{{ mode === 'root' ? '根域列表' : '任务列表' }}
        </span>
        <span class="mono muted">{{ loading ? 'loading…' : items.length + (mode === 'root' ? ' groups' : ' tasks') }}</span>
      </div>
      <div class="table-wrap">
        <table class="table">
          <template v-if="mode === 'root'">
            <thead>
              <tr>
                <th>根域</th><th>资产</th><th>站点</th><th>域名</th><th>Web</th><th>小程序</th><th>APP</th>
                <th>独立 IP</th><th>最近存活</th><th>新增</th><th></th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="g in items" :key="g.root_domain">
                <td class="mono">
                  <a class="num-link" @click="openGroup(g.root_domain)">
                    <Icon name="globe" :size="12" style="color: var(--cyan-2); margin-right: 5px" />{{ g.root_domain }}
                  </a>
                </td>
                <td class="mono">{{ g.cnt }}</td>
                <td class="mono">{{ g.sites }}</td>
                <td class="mono">{{ g.domains }}</td>
                <td class="mono"><a class="num-link" @click="openRootAssets(g.root_domain, 'web')">{{ g.web || 0 }}</a></td>
                <td class="mono"><a class="num-link" :class="{ dim: !g.applet }" @click="openRootAssets(g.root_domain, 'applet')">{{ g.applet || 0 }}</a></td>
                <td class="mono"><a class="num-link" :class="{ dim: !g.app }" @click="openRootAssets(g.root_domain, 'app')">{{ g.app || 0 }}</a></td>
                <td class="mono">{{ g.ips }}</td>
                <td class="mono muted">{{ fmtTime(g.last_seen) }}</td>
                <td>
                  <span v-if="changes[g.root_domain]?.new_count" class="tag warn">+{{ changes[g.root_domain].new_count }}</span>
                  <span v-else class="muted">—</span>
                </td>
                <td style="text-align: right">
                  <button class="btn xs" @click="openGroup(g.root_domain)"><Icon name="eye" :size="11" />查看</button>
                </td>
              </tr>
              <tr v-if="!items.length && !loading">
                <td colspan="11"><div class="empty"><Icon name="group" :size="22" />还没有根域资产，先跑一个任务</div></td>
              </tr>
            </tbody>
          </template>

          <template v-else>
            <thead>
              <tr>
                <th>任务</th><th>资产</th><th>Web</th><th>小程序</th><th>APP</th><th>网段</th><th>主体/邮箱</th>
                <th>状态</th><th>最近入库</th><th></th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="g in items" :key="g.task_id">
                <td>
                  <div class="task-cell">
                    <span class="ellipsis">{{ g.name || g.target || g.task_id }}</span>
                    <span class="mono muted" style="font-size: 11px">{{ g.task_id }}</span>
                  </div>
                </td>
                <td class="mono">{{ g.total }}</td>
                <td class="mono"><a class="num-link" @click="openAssets(g, 'web')">{{ g.web }}</a></td>
                <td class="mono"><a class="num-link" :class="{ dim: !g.applet }" @click="openAssets(g, 'applet')">{{ g.applet }}</a></td>
                <td class="mono"><a class="num-link" :class="{ dim: !g.app }" @click="openAssets(g, 'app')">{{ g.app }}</a></td>
                <td class="mono"><a class="num-link" :class="{ dim: !g.netblock }" @click="openAssets(g, 'netblock')">{{ g.netblock }}</a></td>
                <td class="mono muted">{{ g.meta }}</td>
                <td>
                  <span class="tag" :class="g.status === 'done' ? 'ok' : g.status === 'running' ? 'cyan' : 'info'">
                    {{ STATUS_LABEL[g.status] || g.status || '-' }}
                  </span>
                </td>
                <td class="mono muted">{{ fmtTime(g.last_seen || g.updated_at) }}</td>
                <td style="text-align: right">
                  <button class="btn xs" @click="openTask(g)"><Icon name="eye" :size="11" />任务</button>
                  <button class="btn xs ghost" @click="openAssets(g, '')">资产</button>
                </td>
              </tr>
              <tr v-if="!items.length && !loading">
                <td colspan="10"><div class="empty"><Icon name="layers" :size="22" />还没有任务</div></td>
              </tr>
            </tbody>
          </template>
        </table>
      </div>
    </div>
  </div>
</template>

<style scoped>
.search-row { display: flex; gap: 8px; align-items: center; }
.search-box {
  display: flex; align-items: center; gap: 8px; flex: 1; height: 36px; padding: 0 12px;
  border-radius: 10px; border: 1px solid var(--line);
  background: var(--input-bg, rgba(120, 200, 220, 0.04)); color: var(--muted);
}
.search-box:focus-within { border-color: var(--accent, #34e5c8); }
.search-input { flex: 1; background: transparent; border: 0; outline: none; color: var(--text); font-size: 13px; }
.search-clear { background: transparent; border: 0; color: var(--muted); cursor: pointer; display: flex; }

.dist { display: flex; flex-direction: column; gap: 6px; }
.dist-row {
  display: grid; grid-template-columns: minmax(140px, 1.1fr) minmax(80px, 2fr) 64px minmax(120px, 1fr);
  align-items: center; gap: 10px; padding: 5px 6px; border-radius: 7px;
  background: transparent; border: 0; cursor: pointer; text-align: left; color: var(--text-2);
}
.dist-row:hover { background: var(--hover, rgba(120, 200, 220, 0.07)); }
.dist-name { font-size: 11.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.dist-bar { height: 7px; border-radius: 4px; background: rgba(120, 200, 220, 0.13); overflow: hidden; }
.dist-fill { display: block; height: 100%; border-radius: 4px; background: linear-gradient(90deg, #21b8a5, #34e5c8); }
.dist-num { font-size: 11.5px; text-align: right; color: var(--text); }
.dist-sub { font-size: 10.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

.task-cell { display: flex; flex-direction: column; gap: 2px; max-width: 320px; }
.num-link { color: var(--cyan-2); cursor: pointer; border-bottom: 1px dashed transparent; }
.num-link:hover { border-bottom-color: var(--cyan-2); }
.num-link.dim { color: var(--text-3); }
@media (max-width: 760px) {
  .dist-row { grid-template-columns: minmax(110px, 1.2fr) minmax(60px, 1.4fr) 48px; }
  .dist-sub { display: none; }
}
</style>
