<script setup>
import { computed, onMounted, ref } from 'vue'
import PageHead from '@/components/PageHead.vue'
import Icon from '@/components/Icon.vue'
import { listPocs, readPoc, savePoc, deletePoc, importPocs } from '@/api/endpoints'

const items = ref([])
const dir = ref('')
const scanDirs = ref([])
const loading = ref(false)
const error = ref('')
const notice = ref('')

const keyword = ref('')
const sevFilter = ref('')

const editor = ref({ open: false, name: '', text: '', creating: true, busy: false })
const importer = ref({ open: false, text: '', busy: false, result: null })

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'unknown']
const SEVERITY_LABEL = {
  critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息', unknown: '未标',
}
const SEVERITY_TAG = {
  critical: 'err', high: 'warn', medium: 'cyan', low: 'info', info: 'ok', unknown: '',
}

const SAMPLE = `id: example-demo-check
info:
  name: 示例：接口回显可执行命令
  author: me
  severity: high
  description: 换成你自己的检测逻辑；这条只是格式样例
  tags: rce,demo
requests:
  - method: GET
    path:
      - "{{BaseURL}}/api/ping?cmd=id"
    matchers:
      - type: word
        words:
          - "uid="
`

const counts = computed(() => {
  const out = { total: items.value.length }
  for (const s of SEVERITY_ORDER) out[s] = 0
  for (const it of items.value) {
    const k = SEVERITY_ORDER.includes(it.severity) ? it.severity : 'unknown'
    out[k] += 1
  }
  return out
})

const shown = computed(() => {
  const kw = keyword.value.trim().toLowerCase()
  return items.value.filter((it) => {
    if (sevFilter.value) {
      const k = SEVERITY_ORDER.includes(it.severity) ? it.severity : 'unknown'
      if (k !== sevFilter.value) return false
    }
    if (!kw) return true
    return [it.name, it.id, it.title, it.author, (it.tags || []).join(' ')]
      .join(' ').toLowerCase().includes(kw)
  })
})

const bad = computed(() => items.value.filter((it) => !it.ok).length)

function flash(msg) {
  notice.value = msg
  setTimeout(() => { if (notice.value === msg) notice.value = '' }, 3600)
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    const res = await listPocs()
    items.value = res.items || []
    dir.value = res.dir || ''
    scanDirs.value = res.scan_dirs || []
  } catch (e) {
    error.value = e?.response?.data?.detail || e.message || '模板列表加载失败'
  } finally {
    loading.value = false
  }
}

function openNew() {
  error.value = ''
  editor.value = { open: true, name: '', text: SAMPLE, creating: true, busy: false }
}

async function openEdit(it) {
  error.value = ''
  try {
    const res = await readPoc(it.name)
    editor.value = { open: true, name: res.name, text: res.content || '', creating: false, busy: false }
  } catch (e) {
    error.value = e?.response?.data?.detail || '读取模板失败'
  }
}

async function submit() {
  const name = (editor.value.name || '').trim()
  if (!name) {
    error.value = '模板文件名不能为空（不写后缀会自动补 .yaml）'
    return
  }
  editor.value.busy = true
  error.value = ''
  try {
    const res = await savePoc({ name, content: editor.value.text })
    editor.value.open = false
    flash(`已保存 ${res.name}（${res.id}）`)
    await load()
  } catch (e) {
    error.value = e?.response?.data?.detail || e.message || '保存失败'
  } finally {
    editor.value.busy = false
  }
}

async function remove(it) {
  if (!confirm(`删除模板「${it.name}」？删掉后 nuclei 不再用这条扫。`)) return
  error.value = ''
  try {
    await deletePoc(it.name)
    flash(`已删除 ${it.name}`)
    await load()
  } catch (e) {
    error.value = e?.response?.data?.detail || '删除失败'
  }
}

function openImport() {
  importer.value = { open: true, text: '', busy: false, result: null }
}

async function doImport() {
  if (!(importer.value.text || '').trim()) return
  importer.value.busy = true
  error.value = ''
  try {
    const res = await importPocs({ content: importer.value.text })
    importer.value.result = res
    await load()
  } catch (e) {
    error.value = e?.response?.data?.detail || e.message || '导入失败'
  } finally {
    importer.value.busy = false
  }
}

function sizeText(n) {
  if (n > 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${n} B`
}

function sevLabel(s) {
  return SEVERITY_LABEL[s] || s || '未标'
}

onMounted(load)
</script>

<template>
  <div class="stack">
    <PageHead
      title="POC 管理"
      desc="nuclei 模板库：这里的每一份 YAML 都是 nuclei 真正扫描用的模板；保存后自动成为扫描目录（-t），调用 nuclei 的任务立刻能用上">
      <template #actions>
        <button class="btn sm" @click="load"><Icon name="refresh" :size="13" />刷新</button>
        <button class="btn sm" @click="openImport"><Icon name="upload" :size="13" />批量导入</button>
        <button class="btn primary sm" @click="openNew"><Icon name="plus" :size="13" />新建 POC</button>
      </template>
    </PageHead>

    <div class="metric-row">
      <div class="metric">
        <div class="metric-label">模板总数</div>
        <div class="metric-value mono">{{ counts.total.toLocaleString() }}</div>
        <div class="metric-foot">{{ bad ? `${bad} 份格式有问题` : '全部通过格式校验' }}</div>
      </div>
      <div v-for="s in SEVERITY_ORDER" :key="s" class="metric clickable" @click="sevFilter = sevFilter === s ? '' : s">
        <div class="metric-label">{{ sevLabel(s) }}</div>
        <div class="metric-value mono">{{ counts[s].toLocaleString() }}</div>
        <div class="metric-foot">{{ sevFilter === s ? '已按此筛选，再点取消' : '点一下只看这一档' }}</div>
      </div>
    </div>

    <div v-if="error" class="panel" style="border-color: rgba(255, 100, 112, 0.36)">
      <div class="panel-body" style="color: var(--red-ink); font-size: 12px">{{ error }}</div>
    </div>
    <div v-if="notice" class="panel">
      <div class="panel-body" style="color: var(--ok-text); font-size: 12px">{{ notice }}</div>
    </div>

    <div class="panel">
      <div class="panel-head">
        <span><Icon name="bug" :size="13" />nuclei 模板</span>
        <div class="flex gap-8">
          <input v-model="keyword" class="input mono" style="width: 220px" placeholder="搜模板 id / 名称 / 标签" />
          <select v-model="sevFilter" class="select" style="width: 120px">
            <option value="">全部等级</option>
            <option v-for="s in SEVERITY_ORDER" :key="s" :value="s">{{ sevLabel(s) }}</option>
          </select>
          <span class="mono muted" style="font-size: 10.5px">{{ shown.length }} / {{ items.length }}</span>
        </div>
      </div>
      <div class="table-wrap">
        <table class="table">
          <thead>
            <tr>
              <th style="width: 74px">等级</th>
              <th>模板 id</th>
              <th>名称</th>
              <th>标签</th>
              <th style="width: 110px">作者</th>
              <th style="width: 84px">大小</th>
              <th style="width: 132px">更新</th>
              <th style="width: 116px"></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="it in shown" :key="it.name">
              <td>
                <span class="tag" :class="SEVERITY_TAG[it.severity] || ''">{{ sevLabel(it.severity) }}</span>
              </td>
              <td class="mono" style="color: var(--text)">
                <span class="ellipsis" style="display: inline-block; max-width: 240px" :title="it.name">{{ it.id || it.name }}</span>
                <span v-if="!it.ok" class="tag err" style="margin-left: 6px" :title="it.error">格式错误</span>
              </td>
              <td>
                <div class="ellipsis" style="max-width: 320px" :title="it.title">{{ it.title || '-' }}</div>
                <div v-if="it.error" class="muted" style="font-size: 10.5px">{{ it.error }}</div>
              </td>
              <td>
                <span v-for="t in (it.tags || []).slice(0, 3)" :key="t" class="tag" style="margin-right: 4px">{{ t }}</span>
                <span v-if="!(it.tags || []).length" class="muted">-</span>
              </td>
              <td class="mono muted ellipsis" :title="it.author">{{ it.author || '-' }}</td>
              <td class="mono muted">{{ sizeText(it.bytes) }}</td>
              <td class="mono muted">{{ it.updated }}</td>
              <td style="text-align: right; white-space: nowrap">
                <button class="btn xs" @click="openEdit(it)"><Icon name="terminal" :size="11" />编辑</button>
                <button class="btn xs danger" style="margin-left: 4px" @click="remove(it)"><Icon name="trash" :size="11" /></button>
              </td>
            </tr>
            <tr v-if="!shown.length && !loading">
              <td colspan="8">
                <div class="empty">
                  <Icon name="bug" :size="22" />
                  {{ items.length ? '没有匹配的模板，换个关键词或等级' : '还没有 POC。新建一份或批量导入 nuclei 模板，保存后扫描立刻生效' }}
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="panel-body" style="padding-top: 0">
        <div class="muted mono" style="font-size: 10.5px; line-height: 1.7">
          模板目录：{{ dir || '-' }}<br />
          nuclei 扫描目录：{{ scanDirs.length ? scanDirs.join(' , ') : '暂无（目录为空，或本机没有默认模板库）' }}
        </div>
      </div>
    </div>

    <div v-if="editor.open" class="overlay" @click.self="editor.open = false">
      <div class="modal wide">
        <div class="modal-head">
          <Icon name="bug" :size="15" style="color: var(--cyan)" />
          <span class="flex-1">{{ editor.creating ? '新建 POC' : `编辑 ${editor.name}` }}</span>
          <button class="btn ghost sm" @click="editor.open = false"><Icon name="close" :size="13" /></button>
        </div>
        <div class="modal-body stack" style="gap: 10px">
          <div class="field">
            <span class="field-label">文件名</span>
            <input v-model="editor.name" class="input mono" :disabled="!editor.creating"
                   placeholder="例如：cve-2024-1234.yaml" />
            <span class="field-hint">字母、数字、下划线、点、减号，自动补 .yaml；模板里的 id 才是 nuclei 认的名字</span>
          </div>
          <div class="field">
            <span class="field-label">模板内容（nuclei YAML）</span>
            <textarea v-model="editor.text" class="textarea mono" rows="20" spellcheck="false"></textarea>
            <span class="field-hint">保存前会校验 id、info 和请求段，缺一个都会直接拒，避免存进去扫不了</span>
          </div>
        </div>
        <div class="modal-foot">
          <button class="btn sm" @click="editor.text = SAMPLE"><Icon name="file" :size="12" />填入示例</button>
          <button class="btn sm" @click="editor.open = false">取消</button>
          <button class="btn primary sm" :disabled="editor.busy" @click="submit">
            <Icon name="check" :size="12" />{{ editor.busy ? '保存中…' : '保存' }}
          </button>
        </div>
      </div>
    </div>

    <div v-if="importer.open" class="overlay" @click.self="importer.open = false">
      <div class="modal wide">
        <div class="modal-head">
          <Icon name="upload" :size="15" style="color: var(--cyan)" />
          <span class="flex-1">批量导入 nuclei 模板</span>
          <button class="btn ghost sm" @click="importer.open = false"><Icon name="close" :size="13" /></button>
        </div>
        <div class="modal-body stack" style="gap: 10px">
          <div class="field">
            <span class="field-label">粘贴一份或多份模板</span>
            <textarea v-model="importer.text" class="textarea mono" rows="16" spellcheck="false"
                      placeholder="多份模板之间用一行 --- 分隔；文件名按各自 id 自动生成"></textarea>
            <span class="field-hint">单份格式不对只跳过那一份，其余照常入库</span>
          </div>
          <div v-if="importer.result" class="stack" style="gap: 6px">
            <div class="tag ok" style="height: auto; padding: 4px 8px">成功导入 {{ importer.result.count }} 份</div>
            <div v-for="(f, i) in importer.result.failed" :key="i" class="tag err"
                 style="height: auto; padding: 4px 8px; white-space: normal">
              {{ f.head || '模板' }} · {{ f.error }}
            </div>
          </div>
        </div>
        <div class="modal-foot">
          <button class="btn sm" @click="importer.open = false">关闭</button>
          <button class="btn primary sm" :disabled="importer.busy" @click="doImport">
            <Icon name="upload" :size="12" />{{ importer.busy ? '导入中…' : '导入' }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>
