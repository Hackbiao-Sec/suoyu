<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import PageHead from '@/components/PageHead.vue'
import Icon from '@/components/Icon.vue'
import { diff as fetchDiff, deleteAssets, listAssets, presets as fetchPresets } from '@/api/endpoints'

const route = useRoute()
const router = useRouter()
const root = computed(() => String(route.params.root))

const items = ref([])
const total = ref(0)
const loading = ref(false)
const kind = ref('')
const keyword = ref('')
const change = ref(null)
const picked = ref([])
const deleting = ref(false)
const page = ref(1)
const PAGE_SIZE = 100

const KIND_LABEL = {
  site: '站点', domain: '域名', ip: 'IP', service: '服务', port: '端口', cidr: 'C 段', email: '邮箱',
  leak: '泄露', vuln: '漏洞', takeover: '子域接管', icp: '备案', enterprise: '企业', equity: '股权',
  branch: '分支机构', holds: '控股企业', invest: '对外投资', partner: '股东', copyright: '软著',
  applet: '小程序', wxmp: '公众号', mobile: 'APP', applet_icp: '小程序备案', applet_hint: '小程序线索',
  nuclei: 'POC 命中',
}

const kinds = computed(() => {
  const map = {}
  for (const a of items.value) map[a.kind] = (map[a.kind] || 0) + 1
  return Object.entries(map).map(([k, v]) => ({ kind: k, count: v })).sort((a, b) => b.count - a.count)
})

const shown = computed(() => {
  const kw = keyword.value.trim().toLowerCase()
  return items.value.filter((a) => {
    if (kind.value && a.kind !== kind.value) return false
    if (!kw) return true
    return [a.url, a.title, a.ip, a.fingerprint, a.server, a.sources, a.port]
      .some((v) => String(v ?? '').toLowerCase().includes(kw))
  })
})

const pageRows = computed(() => shown.value.slice((page.value - 1) * PAGE_SIZE, page.value * PAGE_SIZE))
const pageCount = computed(() => Math.max(1, Math.ceil(shown.value.length / PAGE_SIZE)))

const allPicked = computed(() => pageRows.value.length > 0 && pageRows.value.every((a) => picked.value.includes(a.id)))

const newCount = computed(() => items.value.filter((a) => a.is_new).length)
const ips = computed(() => new Set(items.value.filter((a) => a.ip && !a.cdn).map((a) => a.ip)).size)

async function load() {
  loading.value = true
  try {
    const [res, df] = await Promise.all([
      listAssets({ root_domain: root.value, limit: 2000 }),
      fetchDiff(root.value).catch(() => ({ items: [] })),
    ])
    items.value = res.items || []
    total.value = res.total || items.value.length
    change.value = (df.items || [])[0] || null
    picked.value = []
    page.value = 1
  } finally {
    loading.value = false
  }
}

function toggleAll() {
  const ids = pageRows.value.map((a) => a.id)
  if (allPicked.value) picked.value = picked.value.filter((i) => !ids.includes(i))
  else picked.value = [...new Set([...picked.value, ...ids])]
}

function toggleOne(id) {
  picked.value = picked.value.includes(id)
    ? picked.value.filter((i) => i !== id)
    : [...picked.value, id]
}

// 批量删资产：删掉后任务关联一起清，所以先让人看清条数再动手
async function removePicked() {
  if (!picked.value.length) return
  try {
    await ElMessageBox.confirm(
      `确认删除选中的 ${picked.value.length} 条资产？删除后任务关联一并清掉，不可恢复。`,
      '批量删除资产',
      { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' },
    )
  } catch {
    return
  }
  deleting.value = true
  try {
    const res = await deleteAssets(picked.value)
    ElMessage.success(`已删除 ${res.removed ?? picked.value.length} 条资产`)
    await load()
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || '删除失败')
  } finally {
    deleting.value = false
  }
}

async function recollect() {
  const list = await fetchPresets().catch(() => ({ items: [] }))
  const standard = (list.items || []).find((p) => p.key === 'standard')
  const http = (await import('@/api/http')).default
  const res = await http.post('/api/tasks', {
    targets: [root.value],
    name: `资产组重扫-${root.value}`,
    options: standard?.options || {},
  })
  if (res?.task_id) router.push(`/tasks/${res.task_id}`)
}

function fmtTime(ts) {
  if (!ts) return '-'
  const d = new Date(ts * 1000)
  const p = (n) => String(n).padStart(2, '0')
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

onMounted(load)
</script>

<template>
  <div class="stack">
    <PageHead :title="`资产组 · ${root}`" desc="这个根域下的全部资产、端口与站点；勾选后可批量删除，支持组内搜索与类型过滤">
      <template #actions>
        <button class="btn sm" @click="router.push('/groups')"><Icon name="chevron" :size="12" />返回资产组</button>
        <button class="btn sm" @click="load"><Icon name="refresh" :size="12" />刷新</button>
        <button class="btn primary sm" @click="recollect"><Icon name="bolt" :size="12" />重扫本组</button>
      </template>
    </PageHead>

    <div class="metric-row">
      <div class="metric"><span class="metric-label">ASSETS</span><span class="metric-value">{{ total.toLocaleString() }}</span><span class="metric-foot">组内资产</span></div>
      <div class="metric"><span class="metric-label">IPS</span><span class="metric-value">{{ ips }}</span><span class="metric-foot">非 CDN 独立 IP</span></div>
      <div class="metric"><span class="metric-label">NEW</span><span class="metric-value">{{ change?.new_count || newCount }}</span><span class="metric-foot">最近一轮新增</span></div>
      <div class="metric">
        <span class="metric-label">LAST DIFF</span>
        <span class="metric-value" style="font-size: 15px">{{ fmtTime(change?.created_at) }}</span>
        <span class="metric-foot">变更快照时间</span>
      </div>
    </div>

    <div v-if="change?.items?.length" class="panel">
      <div class="panel-head"><span><Icon name="flow" :size="13" />最近新增资产</span><span class="tag warn">+{{ change.new_count }}</span></div>
      <div class="panel-body">
        <div v-for="(u, i) in change.items.slice(-20).reverse()" :key="i" class="mono ellipsis" style="font-size: 11.5px; color: var(--text-2); padding: 2px 0">
          {{ u }}
        </div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-head">
        <span><Icon name="list" :size="13" />组内资产</span>
        <span class="mono muted">{{ shown.length }} / {{ items.length }}</span>
      </div>
      <div class="panel-body stack" style="gap: 10px">
        <div class="row" style="gap: 8px; flex-wrap: wrap; align-items: center">
          <div class="search-box">
            <Icon name="search" :size="13" />
            <input v-model="keyword" class="search-input" placeholder="在「{{ root }}」里搜域名 / 标题 / IP / 指纹" @input="page = 1" />
          </div>
          <button
            v-if="picked.length"
            class="btn xs danger"
            :disabled="deleting"
            @click="removePicked"
          >
            <Icon name="trash" :size="12" />删除选中 {{ picked.length }}
          </button>
          <button v-if="picked.length" class="btn xs" @click="picked = []">清空选择</button>
          <span class="tip flex-1">勾选表头可全选本页；删除会同时清掉任务里的关联记录。</span>
        </div>

        <div class="row" style="gap: 6px; flex-wrap: wrap">
          <button class="btn xs" :class="{ primary: kind === '' }" @click="kind = ''; page = 1">全部 {{ items.length }}</button>
          <button
            v-for="k in kinds"
            :key="k.kind"
            class="btn xs"
            :class="{ primary: kind === k.kind }"
            @click="kind = k.kind; page = 1"
          >
            {{ KIND_LABEL[k.kind] || k.kind }} {{ k.count }}
          </button>
        </div>
      </div>

      <div class="table-wrap">
        <table class="table">
          <thead>
            <tr>
              <th style="width: 34px"><input type="checkbox" :checked="allPicked" @change="toggleAll" /></th>
              <th>类型</th><th>地址</th><th>标题</th><th>状态</th><th>IP</th><th>端口</th>
              <th>指纹</th><th>服务器</th><th>来源</th><th>最近</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="a in pageRows" :key="a.id" :class="{ picked: picked.includes(a.id) }">
              <td><input type="checkbox" :checked="picked.includes(a.id)" @change="toggleOne(a.id)" /></td>
              <td><span class="tag">{{ KIND_LABEL[a.kind] || a.kind }}</span></td>
              <td class="mono cell-url" :title="a.url">
                <a :href="a.url.startsWith('http') ? a.url : undefined" target="_blank" rel="noopener">{{ a.url }}</a>
                <span v-if="a.is_new" class="tag warn" style="margin-left: 6px">NEW</span>
              </td>
              <td class="ellipsis" style="max-width: 220px" :title="a.title">{{ a.title }}</td>
              <td class="mono">{{ a.status_code || '-' }}</td>
              <td class="mono">{{ a.ip }}</td>
              <td class="mono">{{ a.port || '-' }}</td>
              <td class="ellipsis" style="max-width: 180px">{{ a.fingerprint }}</td>
              <td class="ellipsis" style="max-width: 110px">{{ a.server }}</td>
              <td class="muted ellipsis" style="max-width: 140px">{{ a.sources }}</td>
              <td class="mono muted">{{ fmtTime(a.last_seen) }}</td>
            </tr>
            <tr v-if="!pageRows.length && !loading">
              <td colspan="11"><div class="empty"><Icon name="group" :size="22" />{{ keyword || kind ? '当前筛选没有资产' : '这个根域下暂无资产' }}</div></td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="panel-body row" style="justify-content: space-between; align-items: center; gap: 8px">
        <span class="mono muted">第 {{ page }} / {{ pageCount }} 页 · 每页 {{ PAGE_SIZE }}</span>
        <span class="row" style="gap: 6px">
          <button class="btn xs" :disabled="page <= 1" @click="page -= 1">上一页</button>
          <button class="btn xs" :disabled="page >= pageCount" @click="page += 1">下一页</button>
        </span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.search-box {
  display: flex; align-items: center; gap: 7px; min-width: 260px; flex: 1;
  height: 30px; padding: 0 10px; border-radius: 8px;
  border: 1px solid var(--line); background: var(--input-bg, rgba(120, 200, 220, 0.04));
  color: var(--muted);
}
.search-input { flex: 1; background: transparent; border: 0; outline: none; color: var(--text); font-size: 12px; }
tr.picked { background: rgba(52, 229, 200, 0.06); }
</style>
