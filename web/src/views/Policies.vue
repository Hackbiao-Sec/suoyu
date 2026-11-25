<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import PageHead from '@/components/PageHead.vue'
import Icon from '@/components/Icon.vue'
import { getConfig, listPolicies, savePolicy, deletePolicy, applyPolicy } from '@/api/endpoints'

const items = ref([])
const loading = ref(false)
const saving = ref(false)
const selectedId = ref('')
const section = ref('policy')

const cur = reactive({ id: '', name: '', desc: '', builtin: 0 })

const policy = reactive({
  scope_keywords: [],
  exclude_domains: [],
  only_root_domain: false,
  allowed_suffix: '',
  max_subdomain: 200000,
  cdn_exclude: true,
})
const scan = reactive({
  enterprise: true,
  domain_brute: true,
  domain_dict: 'domain_2w.txt',
  alt_dns: true,
  port_scan: true,
  port_type: 'top100',
  port_custom: '',
  port_exclude: '',
  port_timeout: 2.0,
  port_concurrent: 300,
  port_qps: 0,
  port_resume: false,
  port_ip_concurrent: 0,
  port_ip_gap: 0,
  domain_brute_concurrent: 800,
  domain_brute_gap: 0,
  service_detect: true,
  site_spider: true,
  file_leak: true,
  vhost_collision: false,
  sibling: true,
  asn_expand: true,
  asn_scan_blocks: true,
  asn_block_limit: 6,
  equity_ratio: 100,
  equity_depth: 2,
  equity_budget: 40,
  equity_sleep: 1.5,
  enterprise_concurrent: 1,
  enterprise_gap: 0,
  icp_gap: 0,
  equity_ubo_threshold: 25,
  equity_ubo_levels: 1,
  equity_ubo_branches: 3,
  fuzz_dict: 'dir_default.txt',
  dns_source_policy: 'all',
  space_mapping: true,
  space_size: 100,
  space_max_roots: 0,
})
const deep = reactive({
  code_leak: true,
  email_harvest: true,
  mail_dns: true,
  bucket_enum: false,
  screenshot: false,
  nuclei: false,
  nuclei_path: 'nuclei',
  nuclei_severity: 'critical,high',
  ai_search: false,
  ai_triage: true,
})
const httpOpt = reactive({
  timeout: 12,
  concurrent: 100,
  verify: false,
  follow_redirects: true,
  user_agent: '',
})
// 要登录态的工商 / 备案 / 测绘站点：同一来源连着打就会被判风控，这里统一控节奏
const throttle = reactive({
  enabled: true,
  min_interval: 1.5,
  max_interval: 4.0,
  concurrent: 1,
  risk_threshold: 3,
  cooldown: 60,
  cooldown_max: 900,
})
const perSource = reactive({
  aiqicha: { min_interval: 2.5, max_interval: 6.0 },
  tianyancha: { min_interval: 2.5, max_interval: 6.0 },
  qichacha: { min_interval: 3.0, max_interval: 7.0 },
  miit: { min_interval: 6.0, max_interval: 9.0 },
})
// 一键收集怎么跑：套这套策略时把这些编排一起带出来
const oneclick = reactive({
  preset: 'standard',
  steps: ['p1', 'p2', 'p3', 'p4', 'p5'],
  expand_enterprise: true,
  expand_mobile: true,
  poc_scan: false,
})

const STEPS = [
  { k: 'p1', label: '主体穿透' },
  { k: 'p2', label: '域名收集' },
  { k: 'p3', label: '空间测绘' },
  { k: 'p4', label: '主动探测' },
  { k: 'p5', label: '深度挖掘' },
]
const PRESETS = [
  { v: 'quick', label: '快速' },
  { v: 'standard', label: '标准' },
  { v: 'deep', label: '深度' },
  { v: 'hunt', label: '只收根域' },
]

const dicts = ref([])
const PORT_TYPES = [
  { v: 'enterprise', label: '企业端口（90 个）' },
  { v: 'slim', label: '精简端口（30 个）' },
  { v: 'top10', label: 'TOP 10' },
  { v: 'top100', label: 'TOP 100' },
  { v: 'top1000', label: 'TOP 1000' },
  { v: 'all', label: '全端口（1-65535）' },
  { v: 'custom', label: '自定义' },
]
const POLICIES = [
  { v: 'all', label: '全部数据源' },
  { v: 'arl13', label: 'ARL 原生 13 源' },
]
const SOURCES = [
  { k: 'aiqicha', label: '爱企查' },
  { k: 'tianyancha', label: '天眼查' },
  { k: 'qichacha', label: '企查查' },
  { k: 'miit', label: '备案（MIIT）' },
]

const SECTIONS = [
  { k: 'policy', label: '范围策略', icon: 'shield' },
  { k: 'scan', label: '采集强度', icon: 'control' },
  { k: 'throttle', label: '风控节流', icon: 'clock' },
  { k: 'deep', label: '深度挖掘', icon: 'route' },
  { k: 'http', label: '网络参数', icon: 'server' },
  { k: 'oneclick', label: '执行编排', icon: 'flow' },
]

const kwText = ref('')
const exText = ref('')

function splitLines(text) {
  return (text || '').split(/[\n,，]/).map((s) => s.trim()).filter(Boolean)
}

function fill(cfg) {
  Object.assign(policy, cfg.policy || {})
  Object.assign(scan, cfg.scan || {})
  Object.assign(deep, cfg.deep || {})
  Object.assign(httpOpt, cfg.http || {})
  const th = cfg.throttle || {}
  Object.assign(throttle, {
    enabled: th.enabled !== false,
    min_interval: th.min_interval ?? 1.5,
    max_interval: th.max_interval ?? 4.0,
    concurrent: th.concurrent ?? 1,
    risk_threshold: th.risk_threshold ?? 3,
    cooldown: th.cooldown ?? 60,
    cooldown_max: th.cooldown_max ?? 900,
  })
  const ps = th.per_source || {}
  for (const k of Object.keys(perSource)) {
    const item = ps[k] || {}
    perSource[k] = {
      min_interval: item.min_interval ?? perSource[k].min_interval,
      max_interval: item.max_interval ?? perSource[k].max_interval,
    }
  }
  kwText.value = (policy.scope_keywords || []).join('\n')
  exText.value = (policy.exclude_domains || []).join('\n')
  Object.assign(oneclick, {
    preset: 'standard',
    steps: STEPS.map((s) => s.k),
    expand_enterprise: true,
    expand_mobile: true,
    poc_scan: false,
  })
}

function select(item) {
  if (!item) return
  selectedId.value = item.id
  cur.id = item.id
  cur.name = item.name
  cur.desc = item.desc || ''
  cur.builtin = item.builtin ? 1 : 0
  const p = item.payload || {}
  fill(p)
  const oc = p.oneclick || {}
  Object.assign(oneclick, {
    preset: oc.preset || 'standard',
    steps: Array.isArray(oc.steps) && oc.steps.length ? [...oc.steps] : STEPS.map((s) => s.k),
    expand_enterprise: oc.expand_enterprise !== false,
    expand_mobile: oc.expand_mobile !== false,
    poc_scan: !!oc.poc_scan,
  })
  section.value = 'policy'
}

async function loadGlobalCfg() {
  try {
    const res = await getConfig()
    return res.config || {}
  } catch {
    return {}
  }
}

async function load() {
  loading.value = true
  try {
    const res = await listPolicies()
    items.value = res.items || []
    if (!items.value.length) {
      await blank()
      return
    }
    select(items.value.find((x) => x.id === selectedId.value) || items.value[0])
  } finally {
    loading.value = false
  }
}

// 新建：默认克隆当前全局配置，省得每次从零填十几项
async function blank() {
  const cfg = await loadGlobalCfg()
  fill(cfg)
  selectedId.value = ''
  cur.id = ''
  cur.name = ''
  cur.desc = ''
  cur.builtin = 0
  section.value = 'policy'
}

function buildPayload() {
  policy.scope_keywords = splitLines(kwText.value)
  policy.exclude_domains = splitLines(exText.value)
  return {
    policy: { ...policy },
    scan: { ...scan },
    throttle: {
      ...throttle,
      per_source: Object.fromEntries(Object.entries(perSource).map(([k, v]) => [k, { ...v }])),
    },
    deep: { ...deep },
    http: { ...httpOpt },
    oneclick: {
      preset: oneclick.preset,
      steps: [...oneclick.steps],
      expand_enterprise: oneclick.expand_enterprise,
      expand_mobile: oneclick.expand_mobile,
      poc_scan: oneclick.poc_scan,
    },
  }
}

async function save() {
  if (!cur.name.trim()) return ElMessage.warning('先给策略起个名字，例如「常用」「深度」')
  saving.value = true
  try {
    const res = await savePolicy({
      id: cur.id || undefined,
      name: cur.name.trim(),
      desc: cur.desc.trim(),
      payload: buildPayload(),
    })
    const item = res.item
    if (item) selectedId.value = item.id
    const list = await listPolicies()
    items.value = list.items || []
    select(items.value.find((x) => x.id === selectedId.value) || items.value[0])
    ElMessage.success('策略已保存，一键收集里可以直接选它')
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || '保存失败')
  } finally {
    saving.value = false
  }
}

// 另存一份：改个名再存，内置策略也能当模板用
function duplicate() {
  cur.id = ''
  cur.builtin = 0
  cur.name = `${cur.name || '策略'} 副本`
  selectedId.value = ''
}

async function remove() {
  if (!cur.id) return
  try {
    await ElMessageBox.confirm(`删除策略「${cur.name}」？已下发的任务不受影响。`, '删除策略', {
      type: 'warning',
      confirmButtonText: '删除',
      cancelButtonText: '取消',
    })
  } catch {
    return
  }
  try {
    await deletePolicy(cur.id)
    const list = await listPolicies()
    items.value = list.items || []
    if (items.value.length) select(items.value[0])
    else await blank()
    ElMessage.success('已删除')
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || '删除失败')
  }
}

async function applyToGlobal() {
  if (!cur.id) return ElMessage.warning('先把策略存下来再应用')
  try {
    await applyPolicy(cur.id)
    ElMessage.success('已写回全局配置，不选策略的任务也按它跑')
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || '应用失败')
  }
}

function toggleStep(k) {
  oneclick.steps = oneclick.steps.includes(k)
    ? oneclick.steps.filter((x) => x !== k)
    : [...oneclick.steps, k]
}

const selected = computed(() => items.value.find((x) => x.id === selectedId.value) || null)

onMounted(async () => {
  await load()
  try {
    const http = (await import('@/api/http')).default
    const res = await http.get('/api/options')
    dicts.value = res.dicts || []
  } catch {
    /* 字典清单拿不到就用默认值 */
  }
})
</script>

<template>
  <div class="stack">
    <PageHead title="策略管理" desc="把范围、强度、节流、深挖、网络参数打包成一套命名策略；一键收集里选中就整轮生效">
      <template #actions>
        <button class="btn sm" @click="load"><Icon name="refresh" :size="13" />重载</button>
        <button class="btn sm" @click="blank"><Icon name="plus" :size="13" />新建策略</button>
        <button class="btn primary sm" :disabled="saving" @click="save"><Icon name="check" :size="13" />保存策略</button>
      </template>
    </PageHead>

    <div class="policy-layout">
      <aside class="panel policy-list">
        <div class="panel-head">
          <span><Icon name="shield" :size="13" />策略库</span>
          <span class="mono muted">{{ items.length }}</span>
        </div>
        <div class="policy-items">
          <button
            v-for="p in items"
            :key="p.id"
            class="policy-item"
            :class="{ on: p.id === selectedId }"
            @click="select(p)"
          >
            <span class="pi-name">
              {{ p.name }}
              <span v-if="p.builtin" class="tag" style="margin-left: 6px">内置</span>
            </span>
            <span class="pi-desc">{{ p.desc || '无说明' }}</span>
          </button>
          <div v-if="!items.length" class="muted" style="padding: 14px; font-size: 11.5px">
            还没有策略，点右上「新建策略」。
          </div>
        </div>
        <div class="policy-hint">
          <span class="hint-k">怎么用</span>
          <p>在「一键收集」顶部选中策略，整轮就按这套参数跑；不选则用全局配置。</p>
          <p>内置策略改完点保存，会存成你自己的策略。</p>
        </div>
      </aside>

      <div class="stack policy-editor">
        <div class="panel">
          <div class="panel-head">
            <span><Icon name="settings" :size="13" />{{ cur.id ? '编辑策略' : '新建策略' }}</span>
            <span v-if="cur.builtin" class="tag warn">内置策略，改动后点保存即自定义</span>
          </div>
          <div class="panel-body stack" style="gap: 10px">
            <div class="row" style="gap: 10px; flex-wrap: wrap">
              <div class="field flex-1" style="min-width: 200px">
                <span class="field-label">策略名称</span>
                <input v-model="cur.name" class="input" placeholder="例如：常用 / 深度 / 只打官网" />
              </div>
              <div class="field flex-1" style="min-width: 240px">
                <span class="field-label">一句话说明</span>
                <input v-model="cur.desc" class="input" placeholder="这套策略适合什么场景" />
              </div>
            </div>
            <div class="editor-foot">
              <button class="btn xs" @click="duplicate"><Icon name="copy" :size="12" />另存为副本</button>
              <button class="btn xs" :disabled="!cur.id" @click="applyToGlobal"><Icon name="download" :size="12" />写回全局配置</button>
              <button class="btn xs danger" :disabled="!cur.id" @click="remove"><Icon name="trash" :size="12" />删除</button>
              <span class="tip flex-1">「写回全局配置」只影响之后不套策略的任务；套了策略的任务一律按策略走。</span>
            </div>
            <div class="seg tabs">
              <button v-for="s in SECTIONS" :key="s.k" :class="{ on: section === s.k }" @click="section = s.k">
                {{ s.label }}
              </button>
            </div>
          </div>
        </div>

        <div v-if="section === 'policy'" class="cards two">
          <div class="panel">
            <div class="panel-head"><span><Icon name="shield" :size="13" />范围过滤</span></div>
            <div class="panel-body stack" style="gap: 12px">
              <div class="field">
                <span class="field-label">名称黑名单（命中即剔除，一行一个）</span>
                <textarea v-model="kwText" class="textarea" style="min-height: 90px" placeholder="cdn&#10;cloudflare" />
              </div>
              <div class="field">
                <span class="field-label">域名黑名单（不收集这些后缀，一行一个）</span>
                <textarea v-model="exText" class="textarea" style="min-height: 90px" placeholder="example-cdn.com" />
              </div>
            </div>
          </div>

          <div class="panel">
            <div class="panel-head"><span><Icon name="filter" :size="13" />收集范围</span></div>
            <div class="panel-body stack" style="gap: 12px">
              <label class="opt" @click="policy.only_root_domain = !policy.only_root_domain"><span class="switch" :class="{ on: policy.only_root_domain }"></span>仅收集目标根域</label>
              <label class="opt" @click="policy.cdn_exclude = !policy.cdn_exclude"><span class="switch" :class="{ on: policy.cdn_exclude }"></span>剔除 CDN 反解域名</label>
              <div class="field">
                <span class="field-label">只收指定后缀</span>
                <input v-model="policy.allowed_suffix" class="input" placeholder="留空表示不限，例如 .gov.cn" />
              </div>
              <div class="field">
                <span class="field-label">最大子域数</span>
                <input v-model.number="policy.max_subdomain" class="input mono" type="number" />
              </div>
            </div>
          </div>
        </div>

        <div v-if="section === 'scan'" class="cards two">
          <div class="panel">
            <div class="panel-head"><span><Icon name="tasks" :size="13" />阶段开关</span></div>
            <div class="panel-body" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 10px">
              <label class="opt" @click="scan.enterprise = !scan.enterprise"><span class="switch" :class="{ on: scan.enterprise }"></span>企业主体</label>
              <label class="opt" @click="scan.domain_brute = !scan.domain_brute"><span class="switch" :class="{ on: scan.domain_brute }"></span>字典爆破</label>
              <label class="opt" @click="scan.alt_dns = !scan.alt_dns"><span class="switch" :class="{ on: scan.alt_dns }"></span>泛解析变体</label>
              <label class="opt" @click="scan.port_scan = !scan.port_scan"><span class="switch" :class="{ on: scan.port_scan }"></span>端口扫描</label>
              <label class="opt" @click="scan.service_detect = !scan.service_detect"><span class="switch" :class="{ on: scan.service_detect }"></span>服务识别</label>
              <label class="opt" @click="scan.site_spider = !scan.site_spider"><span class="switch" :class="{ on: scan.site_spider }"></span>站点爬虫</label>
              <label class="opt" @click="scan.file_leak = !scan.file_leak"><span class="switch" :class="{ on: scan.file_leak }"></span>敏感文件</label>
              <label class="opt" @click="scan.vhost_collision = !scan.vhost_collision"><span class="switch" :class="{ on: scan.vhost_collision }"></span>VHost 碰撞</label>
              <label class="opt" @click="scan.sibling = !scan.sibling"><span class="switch" :class="{ on: scan.sibling }"></span>旁站 C 段</label>
              <label class="opt" @click="scan.asn_expand = !scan.asn_expand"><span class="switch" :class="{ on: scan.asn_expand }"></span>ASN 网段归集</label>
              <label class="opt" @click="scan.asn_scan_blocks = !scan.asn_scan_blocks"><span class="switch" :class="{ on: scan.asn_scan_blocks }"></span>同 ASN 小段扫描</label>
              <label class="opt" @click="scan.space_mapping = !scan.space_mapping"><span class="switch" :class="{ on: scan.space_mapping }"></span>空间测绘</label>
            </div>
          </div>

          <div class="panel">
            <div class="panel-head"><span><Icon name="server" :size="13" />端口与字典</span></div>
            <div class="panel-body stack" style="gap: 12px">
              <div class="field">
                <span class="field-label">端口范围</span>
                <select v-model="scan.port_type" class="select">
                  <option v-for="p in PORT_TYPES" :key="p.v" :value="p.v">{{ p.label }}</option>
                </select>
              </div>
              <div v-if="scan.port_type === 'custom'" class="field">
                <span class="field-label">自定义端口</span>
                <input v-model="scan.port_custom" class="input mono" placeholder="80,443,8080-8090" />
              </div>
              <div class="field">
                <span class="field-label">排除端口</span>
                <input v-model="scan.port_exclude" class="input mono" placeholder="22,3389,6379（从端口组里剔除）" />
              </div>
              <div class="row">
                <div class="field flex-1">
                  <span class="field-label">端口超时（秒）</span>
                  <input v-model.number="scan.port_timeout" class="input mono" type="number" step="0.5" />
                </div>
                <div class="field flex-1">
                  <span class="field-label">端口并发</span>
                  <input v-model.number="scan.port_concurrent" class="input mono" type="number" />
                </div>
              </div>
              <div class="row">
                <div class="field flex-1">
                  <span class="field-label">爆破并发</span>
                  <input v-model.number="scan.domain_brute_concurrent" class="input mono" type="number" />
                </div>
                <div class="field flex-1">
                  <span class="field-label">爆破字典</span>
                  <select v-model="scan.domain_dict" class="select">
                    <option v-for="d in dicts" :key="d" :value="d">{{ d }}</option>
                    <option v-if="!dicts.length" value="domain_2w.txt">domain_2w.txt</option>
                  </select>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div v-if="section === 'throttle'" class="cards two">
          <div class="panel">
            <div class="panel-head"><span><Icon name="clock" :size="13" />全局节流</span></div>
            <div class="panel-body stack" style="gap: 12px">
              <label class="opt" @click="throttle.enabled = !throttle.enabled"><span class="switch" :class="{ on: throttle.enabled }"></span>开启节流</label>
              <div class="row">
                <div class="field flex-1">
                  <span class="field-label">最小间隔（秒）</span>
                  <input v-model.number="throttle.min_interval" class="input mono" type="number" step="0.1" />
                </div>
                <div class="field flex-1">
                  <span class="field-label">最大间隔（秒）</span>
                  <input v-model.number="throttle.max_interval" class="input mono" type="number" step="0.1" />
                </div>
              </div>
              <div class="row">
                <div class="field flex-1">
                  <span class="field-label">同源并发</span>
                  <input v-model.number="throttle.concurrent" class="input mono" type="number" />
                </div>
                <div class="field flex-1">
                  <span class="field-label">风控阈值（次）</span>
                  <input v-model.number="throttle.risk_threshold" class="input mono" type="number" />
                </div>
              </div>
              <div class="row">
                <div class="field flex-1">
                  <span class="field-label">冷却时长（秒）</span>
                  <input v-model.number="throttle.cooldown" class="input mono" type="number" />
                </div>
                <div class="field flex-1">
                  <span class="field-label">冷却上限（秒）</span>
                  <input v-model.number="throttle.cooldown_max" class="input mono" type="number" />
                </div>
              </div>
            </div>
          </div>

          <div class="panel">
            <div class="panel-head"><span><Icon name="globe" :size="13" />分源间隔</span></div>
            <div class="panel-body stack" style="gap: 10px">
              <div v-for="s in SOURCES" :key="s.k" class="row" style="gap: 8px; align-items: flex-end">
                <span style="width: 88px; font-size: 11.5px">{{ s.label }}</span>
                <div class="field flex-1">
                  <span class="field-label">最小</span>
                  <input v-model.number="perSource[s.k].min_interval" class="input mono" type="number" step="0.1" />
                </div>
                <div class="field flex-1">
                  <span class="field-label">最大</span>
                  <input v-model.number="perSource[s.k].max_interval" class="input mono" type="number" step="0.1" />
                </div>
              </div>
              <span class="tip">工商 / 备案主源容易封 IP，间隔别低于 2 秒；写 0 表示跟随全局。</span>
            </div>
          </div>
        </div>

        <div v-if="section === 'deep'" class="cards two">
          <div class="panel">
            <div class="panel-head"><span><Icon name="route" :size="13" />深挖开关</span></div>
            <div class="panel-body" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px">
              <label class="opt" @click="deep.code_leak = !deep.code_leak"><span class="switch" :class="{ on: deep.code_leak }"></span>代码泄露</label>
              <label class="opt" @click="deep.email_harvest = !deep.email_harvest"><span class="switch" :class="{ on: deep.email_harvest }"></span>邮箱收集</label>
              <label class="opt" @click="deep.mail_dns = !deep.mail_dns"><span class="switch" :class="{ on: deep.mail_dns }"></span>邮件 DNS</label>
              <label class="opt" @click="deep.bucket_enum = !deep.bucket_enum"><span class="switch" :class="{ on: deep.bucket_enum }"></span>存储桶枚举</label>
              <label class="opt" @click="deep.screenshot = !deep.screenshot"><span class="switch" :class="{ on: deep.screenshot }"></span>页面截图</label>
              <label class="opt" @click="deep.nuclei = !deep.nuclei"><span class="switch" :class="{ on: deep.nuclei }"></span>Nuclei 复核</label>
              <label class="opt" @click="deep.ai_search = !deep.ai_search"><span class="switch" :class="{ on: deep.ai_search }"></span>AI 搜索</label>
              <label class="opt" @click="deep.ai_triage = !deep.ai_triage"><span class="switch" :class="{ on: deep.ai_triage }"></span>AI 归因</label>
            </div>
          </div>

          <div class="panel">
            <div class="panel-head"><span><Icon name="shield" :size="13" />Nuclei 口径</span></div>
            <div class="panel-body stack" style="gap: 12px">
              <div class="field">
                <span class="field-label">模板级别（复核用）</span>
                <input v-model="deep.nuclei_severity" class="input mono" placeholder="critical,high" />
              </div>
              <div class="field">
                <span class="field-label">nuclei 可执行路径</span>
                <input v-model="deep.nuclei_path" class="input mono" placeholder="nuclei" />
              </div>
              <span class="tip">「Nuclei 复核」按上面的级别跑；一键收集里勾「POC 扫描」则忽略级别、全量扫 POC 管理里的模板。</span>
            </div>
          </div>
        </div>

        <div v-if="section === 'http'" class="cards two">
          <div class="panel">
            <div class="panel-head"><span><Icon name="server" :size="13" />HTTP 网络</span></div>
            <div class="panel-body stack" style="gap: 12px">
              <div class="row">
                <div class="field flex-1">
                  <span class="field-label">超时（秒）</span>
                  <input v-model.number="httpOpt.timeout" class="input mono" type="number" step="1" />
                </div>
                <div class="field flex-1">
                  <span class="field-label">并发</span>
                  <input v-model.number="httpOpt.concurrent" class="input mono" type="number" />
                </div>
              </div>
              <label class="opt" @click="httpOpt.follow_redirects = !httpOpt.follow_redirects"><span class="switch" :class="{ on: httpOpt.follow_redirects }"></span>跟随跳转</label>
              <label class="opt" @click="httpOpt.verify = !httpOpt.verify"><span class="switch" :class="{ on: httpOpt.verify }"></span>校验 TLS 证书</label>
            </div>
          </div>

          <div class="panel">
            <div class="panel-head"><span><Icon name="globe" :size="13" />请求特征</span></div>
            <div class="panel-body stack" style="gap: 12px">
              <div class="field">
                <span class="field-label">User-Agent（留空用默认）</span>
                <input v-model="httpOpt.user_agent" class="input mono" placeholder="Mozilla/5.0 …" />
              </div>
              <div class="field">
                <span class="field-label">同 ASN 小段上限</span>
                <input v-model.number="scan.asn_block_limit" class="input mono" type="number" />
              </div>
              <div class="field">
                <span class="field-label">空间测绘单根域上限（0 = 不限）</span>
                <input v-model.number="scan.space_max_roots" class="input mono" type="number" />
              </div>
            </div>
          </div>
        </div>

        <div v-if="section === 'oneclick'" class="cards two">
          <div class="panel">
            <div class="panel-head"><span><Icon name="flow" :size="13" />一键收集默认编排</span></div>
            <div class="panel-body stack" style="gap: 12px">
              <div class="field">
                <span class="field-label">采集强度</span>
                <select v-model="oneclick.preset" class="select">
                  <option v-for="p in PRESETS" :key="p.v" :value="p.v">{{ p.label }}</option>
                </select>
              </div>
              <div class="field">
                <span class="field-label">执行步骤</span>
                <div class="row" style="gap: 6px; flex-wrap: wrap">
                  <button
                    v-for="s in STEPS"
                    :key="s.k"
                    class="btn xs"
                    :class="{ primary: oneclick.steps.includes(s.k) }"
                    @click="toggleStep(s.k)"
                  >
                    {{ s.label }}
                  </button>
                </div>
              </div>
            </div>
          </div>

          <div class="panel">
            <div class="panel-head"><span><Icon name="aim" :size="13" />开关</span></div>
            <div class="panel-body stack" style="gap: 12px">
              <label class="opt" @click="oneclick.expand_enterprise = !oneclick.expand_enterprise"><span class="switch" :class="{ on: oneclick.expand_enterprise }"></span>企业主体扩展</label>
              <label class="opt" @click="oneclick.expand_mobile = !oneclick.expand_mobile"><span class="switch" :class="{ on: oneclick.expand_mobile }"></span>小程序 / App</label>
              <label class="opt" @click="oneclick.poc_scan = !oneclick.poc_scan"><span class="switch" :class="{ on: oneclick.poc_scan }"></span>POC 全量扫描</label>
              <span class="tip">勾 POC 全量扫描会自动带上「深度挖掘」步骤，用 POC 管理里的全部模板扫，不限级别。</span>
            </div>
          </div>
        </div>

        <div class="action-bar">
          <button class="btn primary" :disabled="saving" @click="save"><Icon name="check" :size="14" />{{ saving ? '保存中…' : '保存策略' }}</button>
          <button v-if="selected" class="btn" :disabled="!cur.id" @click="applyToGlobal"><Icon name="download" :size="14" />写回全局</button>
          <span class="action-tip">{{ cur.id ? `正在编辑：${selected?.name || cur.name}` : '新策略（尚未保存）' }}</span>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.policy-layout { display: grid; grid-template-columns: 236px minmax(0, 1fr); gap: 12px; align-items: start; }
.policy-list { position: sticky; top: 12px; }
.policy-items { display: flex; flex-direction: column; gap: 4px; padding: 8px; max-height: calc(100vh - 200px); overflow-y: auto; }
.policy-item {
  display: flex; flex-direction: column; gap: 4px; text-align: left;
  padding: 9px 10px; border-radius: 8px; border: 1px solid transparent;
  background: transparent; color: var(--text-2); cursor: pointer;
}
.policy-item:hover { background: var(--hover, rgba(120, 200, 220, 0.07)); }
.policy-item.on { border-color: var(--accent, #34e5c8); background: rgba(52, 229, 200, 0.09); color: var(--text); }
.pi-name { font-size: 12.5px; display: flex; align-items: center; }
.pi-desc { font-size: 10.5px; color: var(--muted); line-height: 1.5; }
.policy-hint { border-top: 1px solid var(--line-soft); padding: 10px 12px 12px; display: flex; flex-direction: column; gap: 5px; }
.policy-hint .hint-k { font-size: 10px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--cyan); opacity: 0.85; }
.policy-hint p { margin: 0; font-size: 11px; line-height: 1.65; color: var(--muted); }
.policy-editor { min-width: 0; }
/* 这些类原本只定义在其它视图的 scoped 样式里，跨组件不生效，会串成开关压字 */
.opt { display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--text-2); cursor: pointer; }
.tip { font-size: 11px; line-height: 1.6; color: var(--muted); }
.seg.tabs {
  display: flex; flex-wrap: wrap; gap: 4px;
  margin: 2px -13px -12px; padding: 9px 13px;
  border: 0; border-top: 1px solid var(--line-soft);
  border-radius: 0 0 var(--radius) var(--radius);
  background: rgba(6, 12, 18, 0.4);
}
.seg.tabs button { height: 26px; padding: 0 12px; }
.seg.tabs button.on { box-shadow: none; }
.editor-foot { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; border-top: 1px solid var(--line-soft); padding-top: 10px; }
.policy-editor .cards.two { align-items: start; }
.action-bar {
  position: sticky; bottom: 0; z-index: 6;
  display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
  padding: 9px 12px; border-radius: 10px;
  border: 1px solid var(--line);
  background: linear-gradient(180deg, rgba(12, 24, 33, 0.92), rgba(8, 16, 23, 0.98));
  backdrop-filter: blur(8px);
}
.action-tip { font-size: 11.5px; color: var(--muted); }
/* 白天模式：tab 条与底部动作栏原来是深色实底，白底上会变成灰带和黑条 */
html[data-theme="light"] .seg.tabs { background: #eef4f8; }
html[data-theme="light"] .seg.tabs button.on {
  background: rgba(14, 155, 136, 0.16);
  box-shadow: inset 0 0 0 1px rgba(14, 155, 136, 0.22);
  color: var(--cyan-ink);
}
html[data-theme="light"] .action-bar {
  background: linear-gradient(180deg, rgba(255, 255, 255, 0.95), rgba(248, 252, 254, 0.98));
  box-shadow: 0 -8px 24px rgba(24, 62, 82, 0.08);
}
html[data-theme="light"] .policy-item:hover { background: rgba(14, 155, 136, 0.07); }
html[data-theme="light"] .policy-item.on {
  border-color: var(--cyan);
  background: rgba(14, 155, 136, 0.1);
}
@media (max-width: 900px) {
  .policy-layout { grid-template-columns: minmax(0, 1fr); }
  .policy-list { position: static; }
  .policy-items { max-height: 200px; }
}
</style>
