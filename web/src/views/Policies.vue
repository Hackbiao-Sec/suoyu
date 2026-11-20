<script setup>
import { onMounted, reactive, ref } from 'vue'
import PageHead from '@/components/PageHead.vue'
import Icon from '@/components/Icon.vue'
import { getConfig, saveConfig } from '@/api/endpoints'

const loading = ref(false)
const saving = ref(false)
const saved = ref(false)

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

const SECTIONS = [
  { k: 'policy', label: '范围策略', icon: 'shield' },
  { k: 'scan', label: '采集强度', icon: 'control' },
  { k: 'deep', label: '深度挖掘', icon: 'route' },
  { k: 'http', label: '网络参数', icon: 'server' },
]
const section = ref('policy')

function splitLines(text) {
  return (text || '').split(/[\n,，]/).map((s) => s.trim()).filter(Boolean)
}

const kwText = ref('')
const exText = ref('')

async function load() {
  loading.value = true
  try {
    const res = await getConfig()
    const cfg = res.config || {}
    Object.assign(policy, cfg.policy || {})
    Object.assign(scan, cfg.scan || {})
    Object.assign(deep, cfg.deep || {})
    Object.assign(httpOpt, cfg.http || {})
    kwText.value = (policy.scope_keywords || []).join('\n')
    exText.value = (policy.exclude_domains || []).join('\n')
  } finally {
    loading.value = false
  }
}

async function save() {
  saving.value = true
  saved.value = false
  try {
    policy.scope_keywords = splitLines(kwText.value)
    policy.exclude_domains = splitLines(exText.value)
    await saveConfig({
      policy: { ...policy },
      scan: { ...scan },
      deep: { ...deep },
      http: { ...httpOpt },
    })
    saved.value = true
    setTimeout(() => { saved.value = false }, 2400)
  } finally {
    saving.value = false
  }
}

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
    <PageHead title="策略配置" desc="控制收什么、收多深、走什么网络；这些是任务默认值，任务里也能临时覆盖">
      <template #actions>
        <span v-if="saved" class="tag ok">已保存并生效</span>
        <button class="btn sm" @click="load"><Icon name="refresh" :size="13" />重载</button>
        <button class="btn primary sm" :disabled="saving" @click="save"><Icon name="check" :size="13" />保存配置</button>
      </template>
    </PageHead>

    <div class="row">
      <div class="seg">
        <button v-for="s in SECTIONS" :key="s.k" :class="{ on: section === s.k }" @click="section = s.k">
          {{ s.label }}
        </button>
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
          <label class="opt"><span class="switch" :class="{ on: policy.only_root_domain }" @click="policy.only_root_domain = !policy.only_root_domain" />仅收集目标根域</label>
          <label class="opt"><span class="switch" :class="{ on: policy.cdn_exclude }" @click="policy.cdn_exclude = !policy.cdn_exclude" />剔除 CDN 反解域名</label>
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
          <label class="opt"><span class="switch" :class="{ on: scan.enterprise }" @click="scan.enterprise = !scan.enterprise" />企业主体</label>
          <label class="opt"><span class="switch" :class="{ on: scan.domain_brute }" @click="scan.domain_brute = !scan.domain_brute" />字典爆破</label>
          <label class="opt"><span class="switch" :class="{ on: scan.alt_dns }" @click="scan.alt_dns = !scan.alt_dns" />泛解析变体</label>
          <label class="opt"><span class="switch" :class="{ on: scan.port_scan }" @click="scan.port_scan = !scan.port_scan" />端口扫描</label>
          <label class="opt"><span class="switch" :class="{ on: scan.service_detect }" @click="scan.service_detect = !scan.service_detect" />服务识别</label>
          <label class="opt"><span class="switch" :class="{ on: scan.site_spider }" @click="scan.site_spider = !scan.site_spider" />站点爬虫</label>
          <label class="opt"><span class="switch" :class="{ on: scan.file_leak }" @click="scan.file_leak = !scan.file_leak" />敏感文件</label>
          <label class="opt"><span class="switch" :class="{ on: scan.vhost_collision }" @click="scan.vhost_collision = !scan.vhost_collision" />VHost 碰撞</label>
          <label class="opt"><span class="switch" :class="{ on: scan.sibling }" @click="scan.sibling = !scan.sibling" />旁站 C 段</label>
          <label class="opt"><span class="switch" :class="{ on: scan.asn_expand }" @click="scan.asn_expand = !scan.asn_expand" />ASN 网段归集</label>
          <label class="opt"><span class="switch" :class="{ on: scan.asn_scan_blocks }" @click="scan.asn_scan_blocks = !scan.asn_scan_blocks" />同 ASN 小段扫描</label>
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
              <span class="field-label">每秒连接上限（0 = 不限）</span>
              <input v-model.number="scan.port_qps" class="input mono" type="number" min="0" />
            </div>
            <div class="field flex-1">
              <span class="field-label">断点续扫</span>
              <label class="opt"><span class="switch" :class="{ on: scan.port_resume }" @click="scan.port_resume = !scan.port_resume" />中断后跳过已扫组合</label>
            </div>
          </div>
          <div class="row">
            <div class="field flex-1">
              <span class="field-label">子域字典</span>
              <select v-model="scan.domain_dict" class="select">
                <option v-for="d in dicts.filter((x) => x.includes('domain'))" :key="d" :value="d">{{ d }}</option>
                <option v-if="!dicts.length" :value="scan.domain_dict">{{ scan.domain_dict }}</option>
              </select>
            </div>
            <div class="field flex-1">
              <span class="field-label">目录字典</span>
              <select v-model="scan.fuzz_dict" class="select">
                <option v-for="d in dicts.filter((x) => !x.includes('domain'))" :key="d" :value="d">{{ d }}</option>
                <option v-if="!dicts.length" :value="scan.fuzz_dict">{{ scan.fuzz_dict }}</option>
              </select>
            </div>
          </div>
          <div class="field">
            <span class="field-label">单任务同 ASN 小段扫描上限（个）</span>
            <input v-model.number="scan.asn_block_limit" class="input mono" type="number" min="0" />
            <span class="field-hint">只扫 /24 及更小的宣告段；运营商骨干大段只落网段资产，不扫。</span>
          </div>
          <div class="field">
            <span class="field-label">被动源策略</span>
            <select v-model="scan.dns_source_policy" class="select">
              <option v-for="p in POLICIES" :key="p.v" :value="p.v">{{ p.label }}</option>
            </select>
          </div>
          <div class="field">
            <span class="field-label">空间测绘</span>
            <label class="opt"><span class="switch" :class="{ on: scan.space_mapping }" @click="scan.space_mapping = !scan.space_mapping" />拿已确认根域去测绘引擎反查</label>
            <span class="field-hint">补「域名不解析但对外暴露过」的资产（历史解析、旁路入口）；关掉则不消耗测绘配额。</span>
          </div>
          <div class="row">
            <div class="field flex-1">
              <span class="field-label">每根域每引擎取多少条</span>
              <input v-model.number="scan.space_size" class="input mono" type="number" min="20" max="1000" />
              <span class="field-hint">20～1000。调大可多捞长尾，配额消耗同步变多。</span>
            </div>
            <div class="field flex-1">
              <span class="field-label">根域上限（0 = 不限）</span>
              <input v-model.number="scan.space_max_roots" class="input mono" type="number" min="0" />
              <span class="field-hint">默认 0：本轮确认的根域全部反查，一棵都不漏。填正数才启用熔断，超出按「主目标根优先 + 已收集资产量降序」截断，被砍掉的根域这一轮不会有新资产。</span>
            </div>
          </div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-head"><span><Icon name="tasks" :size="13" />股权穿透</span></div>
        <div class="panel-body stack" style="gap: 12px">
          <div class="field">
            <span class="field-label">控股门槛 %</span>
            <input v-model.number="scan.equity_ratio" class="input mono" type="number" min="0" max="100" />
            <span class="field-hint">达到这条线的子/孙公司才进资产池继续展开：100 只收全资，51 收控盘，0 收全部持股。</span>
          </div>
          <div class="field">
            <span class="field-label">向下穿透层数</span>
            <input v-model.number="scan.equity_depth" class="input mono" type="number" min="1" max="4" />
            <span class="field-hint">2 = 子公司 + 孙公司；3 再往下穿一层。只对已达控股门槛的节点继续展开，参股公司不耗次数。</span>
          </div>
          <div class="field">
            <span class="field-label">穿透请求预算（次 · 0=不限）</span>
            <input v-model.number="scan.equity_budget" class="input mono" type="number" min="0" max="2000" />
            <span class="field-hint">一次约拉一页（100 家公司），额度小的工商账号把这里调小；额度用尽会自动停并写明原因。拉到整棵树常要几十次请求，预算给不到就会截断；填 0 = 不限次数，一直翻到没有下一页，只受每层页上限和执行时限约束。</span>
          </div>
          <div class="field">
            <span class="field-label">查询间隔（秒）</span>
            <input v-model.number="scan.equity_sleep" class="input mono" type="number" min="0" max="300" step="1" />
            <span class="field-hint">每一次工商请求之前额外等待，叠加在节流闸之上——翻页、补穿、重试都吃这一份。慢节奏才拉得全：填 30 就是每分钟 2 次，一次穿透大约要跑十几分钟，下面的执行时限会跟着自动放宽；0 = 不额外等。</span>
          </div>
          <div class="field">
            <span class="field-label">实控线 %</span>
            <input v-model.number="scan.equity_ubo_threshold" class="input mono" type="number" min="1" max="100" />
            <span class="field-hint">最终受益人判定线：股东树逐级折算后的累计持股达到这条线标成控制，25 是工商常用口径。</span>
          </div>
          <div class="field">
            <span class="field-label">上游穿透层数（0 关闭）</span>
            <input v-model.number="scan.equity_ubo_levels" class="input mono" type="number" min="0" max="3" />
            <span class="field-hint">机构股东再往上拉几层股东，才能把人穿到底。每多一层都多花工商次数。</span>
          </div>
          <div class="field">
            <span class="field-label">每层展开机构数</span>
            <input v-model.number="scan.equity_ubo_branches" class="input mono" type="number" min="0" max="20" />
            <span class="field-hint">每层最多展开几家机构股东，遇到风控或额度用尽会自行停下。</span>
          </div>
        </div>
      </div>
    </div>

    <div v-if="section === 'deep'" class="cards two">
      <div class="panel">
        <div class="panel-head"><span><Icon name="route" :size="13" />深度阶段</span></div>
        <div class="panel-body" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 10px">
          <label class="opt"><span class="switch" :class="{ on: deep.code_leak }" @click="deep.code_leak = !deep.code_leak" />代码泄露检索</label>
          <label class="opt"><span class="switch" :class="{ on: deep.email_harvest }" @click="deep.email_harvest = !deep.email_harvest" />邮箱收集</label>
          <label class="opt"><span class="switch" :class="{ on: deep.mail_dns }" @click="deep.mail_dns = !deep.mail_dns" />MX / SPF / DMARC</label>
          <label class="opt"><span class="switch" :class="{ on: deep.bucket_enum }" @click="deep.bucket_enum = !deep.bucket_enum" />存储桶枚举</label>
          <label class="opt"><span class="switch" :class="{ on: deep.screenshot }" @click="deep.screenshot = !deep.screenshot" />站点截图</label>
          <label class="opt"><span class="switch" :class="{ on: deep.nuclei }" @click="deep.nuclei = !deep.nuclei" />Nuclei 模板</label>
          <label class="opt"><span class="switch" :class="{ on: deep.ai_search }" @click="deep.ai_search = !deep.ai_search" />AI 关键词扩展（企业阶段别名 / 产品名）</label>
          <label class="opt"><span class="switch" :class="{ on: deep.ai_triage }" @click="deep.ai_triage = !deep.ai_triage" />任务结束自动写 AI 侦察小结</label>
          <span class="field-hint">两项都需要先在「系统设置 → AI」接入大模型；其它 AI 能力在左侧「AI 工坊」。</span>
        </div>
      </div>

      <div class="panel">
        <div class="panel-head"><span><Icon name="bug" :size="13" />外部工具</span></div>
        <div class="panel-body stack" style="gap: 12px">
          <div class="field">
            <span class="field-label">Nuclei 可执行路径</span>
            <input v-model="deep.nuclei_path" class="input mono" placeholder="nuclei" />
          </div>
          <div class="field">
            <span class="field-label">Nuclei 严重级别</span>
            <input v-model="deep.nuclei_severity" class="input mono" placeholder="critical,high" />
          </div>
          <span class="field-hint">
            存储桶枚举与站点截图会产生大量外部请求，默认关闭；Nuclei 需本机已安装并在 PATH 中。
          </span>
        </div>
      </div>
    </div>

    <div v-if="section === 'http'" class="cards two">
      <div class="panel">
        <div class="panel-head"><span><Icon name="server" :size="13" />HTTP 探测</span></div>
        <div class="panel-body stack" style="gap: 12px">
          <div class="row">
            <div class="field flex-1">
              <span class="field-label">超时（秒）</span>
              <input v-model.number="httpOpt.timeout" class="input mono" type="number" />
            </div>
            <div class="field flex-1">
              <span class="field-label">并发</span>
              <input v-model.number="httpOpt.concurrent" class="input mono" type="number" />
            </div>
          </div>
          <label class="opt"><span class="switch" :class="{ on: httpOpt.verify }" @click="httpOpt.verify = !httpOpt.verify" />校验 TLS 证书</label>
          <label class="opt"><span class="switch" :class="{ on: httpOpt.follow_redirects }" @click="httpOpt.follow_redirects = !httpOpt.follow_redirects" />跟随跳转</label>
        </div>
      </div>
      <div class="panel">
        <div class="panel-head"><span><Icon name="terminal" :size="13" />User-Agent</span></div>
        <div class="panel-body">
          <textarea v-model="httpOpt.user_agent" class="textarea" style="min-height: 90px" />
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.opt { display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--text-2); cursor: pointer; }
</style>
