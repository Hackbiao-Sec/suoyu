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
const importer = ref({
  open: false, text: '', files: [], skipped: [], busy: false, reading: false,
  progress: null, result: null, dropActive: false,
})
const fileInput = ref(null)
const MAX_BYTES = 1024 * 1024
// 一次请求带多少文件/字节；超过就接着发下一批，导入数量本身不设上限
const CHUNK_FILES = 50
const CHUNK_BYTES = 4 * 1024 * 1024
const READ_WORKERS = 8

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
  importer.value = {
    open: true, text: '', files: [], skipped: [], busy: false, reading: false,
    progress: null, result: null, dropActive: false,
  }
}

function pickFiles() {
  if (importer.value.busy || importer.value.reading) return
  fileInput.value?.click()
}

function onPick(ev) {
  addFiles(ev.target?.files)
  if (ev.target) ev.target.value = ''
}

function onDrop(ev) {
  importer.value.dropActive = false
  if (importer.value.busy || importer.value.reading) return
  addFiles(ev.dataTransfer?.files)
}

function readText(file) {
  if (typeof file.text === 'function') return file.text()
  return new Promise((resolve, reject) => {
    const fr = new FileReader()
    fr.onload = () => resolve(String(fr.result || ''))
    fr.onerror = () => reject(fr.error || new Error('读取失败'))
    fr.readAsText(file)
  })
}

async function addFiles(list) {
  const incoming = Array.from(list || [])
  if (!incoming.length) return
  const skipped = [...importer.value.skipped]
  const seen = new Set(importer.value.files.map((x) => x.name))
  const picked = []
  for (const f of incoming) {
    if (!f.size) {
      skipped.push({ name: f.name || '(无文件名)', why: '空文件' })
      continue
    }
    if (!/\.ya?ml$/i.test(f.name || '')) {
      skipped.push({ name: f.name || '(无文件名)', why: '不是 .yaml / .yml' })
      continue
    }
    if (f.size > MAX_BYTES) {
      skipped.push({ name: f.name, why: '单个超过 1 MB' })
      continue
    }
    if (seen.has(f.name)) {
      skipped.push({ name: f.name, why: '同名重复，已忽略' })
      continue
    }
    seen.add(f.name)
    picked.push(f)
  }
  if (picked.length) {
    importer.value.reading = true
    const slots = new Array(picked.length)
    let cursor = 0
    const workers = Array.from({ length: Math.min(READ_WORKERS, picked.length) }, async () => {
      while (cursor < picked.length) {
        const idx = cursor
        cursor += 1
        const f = picked[idx]
        try {
          slots[idx] = { name: f.name, size: f.size, content: await readText(f) }
        } catch (e) {
          skipped.push({ name: f.name, why: '读取失败' })
        }
      }
    })
    await Promise.all(workers)
    importer.value.files = importer.value.files.concat(slots.filter(Boolean))
    importer.value.reading = false
  }
  importer.value.skipped = skipped
  if (picked.length) importer.value.result = null
}

const skipGroups = computed(() => {
  const groups = new Map()
  for (const s of importer.value.skipped) {
    if (!groups.has(s.why)) groups.set(s.why, [])
    groups.get(s.why).push(s.name)
  }
  return Array.from(groups, ([why, names]) => ({ why, names, count: names.length }))
})

function removeFile(i) {
  importer.value.files.splice(i, 1)
}

function clearFiles() {
  if (importer.value.reading) return
  importer.value.files = []
  importer.value.skipped = []
}

function errText(e) {
  const status = e?.response?.status
  const detail = e?.response?.data?.detail
  let msg = ''
  if (Array.isArray(detail)) msg = detail.map((x) => x?.msg || String(x)).join('；')
  else if (typeof detail === 'string') msg = detail
  if (status) return `HTTP ${status}${msg ? ' · ' + msg : ''}`
  if (e?.code === 'ECONNABORTED') return '请求超时，请重试或分批导入'
  return e?.message || '导入失败'
}

// 文件按批上传，每批只带 CHUNK_FILES 个且不超过 CHUNK_BYTES；结果合并后一次展示
async function doImport() {
  const text = (importer.value.text || '').trim()
  const queue = importer.value.files.slice()
  if (!queue.length && !text) return
  const saved = []
  const failed = []
  const total = queue.length
  let sent = 0
  let cursor = 0
  let pendingStart = 0
  let firstRequest = true
  importer.value.busy = true
  importer.value.result = null
  importer.value.progress = total ? { done: 0, total } : null
  error.value = ''
  try {
    while (cursor < queue.length || firstRequest) {
      pendingStart = cursor
      const batch = []
      let bytes = 0
      while (cursor < queue.length && batch.length < CHUNK_FILES
             && (!bytes || bytes + queue[cursor].size <= CHUNK_BYTES)) {
        bytes += queue[cursor].size
        batch.push(queue[cursor])
        cursor += 1
      }
      const res = await importPocs({
        files: batch.map((f) => ({ name: f.name, content: f.content })),
        content: firstRequest ? text : '',
      })
      firstRequest = false
      for (const s of res.saved || []) saved.push(s)
      for (const f of res.failed || []) failed.push(f)
      sent += batch.length
      importer.value.progress = total ? { done: sent, total } : null
    }
    const failedNames = new Set(failed.map((f) => f.file).filter(Boolean))
    importer.value.files = importer.value.files.filter((f) => failedNames.has(f.name))
    const textFailed = failed.some((f) => f.file === '粘贴内容')
    importer.value.text = textFailed ? text : ''
    importer.value.skipped = []
    importer.value.result = { count: saved.length, saved, failed }
    if (saved.length) {
      flash(`成功导入 ${saved.length} 份 nuclei 模板`)
      await load()
    }
    if (!saved.length && failed.length) error.value = '这一批没有导入成功，原因见下方'
  } catch (e) {
    // 没发出去的、以及这一批没拿到回包的，留在列表里方便重试（按文件名覆盖，重发不会重复）
    importer.value.files = queue.slice(pendingStart)
    importer.value.result = (saved.length || failed.length) ? { count: saved.length, saved, failed } : null
    error.value = errText(e)
  } finally {
    importer.value.busy = false
    importer.value.reading = false
    importer.value.progress = null
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
        <div class="modal-body stack" style="gap: 12px">
          <div class="drop" :class="{ active: importer.dropActive }" @click="pickFiles"
               @dragover.prevent="importer.dropActive = true" @dragleave.prevent="importer.dropActive = false"
               @drop.prevent="onDrop">
            <Icon name="upload" :size="20" />
            <div>点这里选择模板文件，或把 .yaml / .yml 拖进来</div>
            <div class="muted" style="font-size: 10.5px">可以一次选多个（Ctrl+A 全选也行，数量不限）；文件名会保留成模板文件名，同名则覆盖旧模板</div>
          </div>
          <input ref="fileInput" type="file" multiple accept=".yaml,.yml" style="display: none" @change="onPick" />

          <div v-if="importer.files.length" class="stack" style="gap: 6px">
            <div class="flex" style="align-items: center; justify-content: space-between">
              <span class="muted" style="font-size: 11px">已选 {{ importer.files.length }} 个文件{{ importer.reading ? '，正在读取…' : '，待导入' }}</span>
              <button class="btn xs" @click="clearFiles">清空</button>
            </div>
            <div class="file-list">
              <div v-for="(f, i) in importer.files" :key="f.name" class="file-row">
                <Icon name="file" :size="11" />
                <span class="mono flex-1 ellipsis" :title="f.name">{{ f.name }}</span>
                <span class="mono muted">{{ sizeText(f.size) }}</span>
                <button class="btn xs danger" @click="removeFile(i)"><Icon name="close" :size="10" /></button>
              </div>
            </div>
          </div>
          <div v-if="importer.skipped.length" class="tag warn skip-box">
            <div>已跳过 {{ importer.skipped.length }} 个文件（不会提交）</div>
            <div v-for="g in skipGroups" :key="g.why" class="skip-line">
              {{ g.why }} × {{ g.count }}<span class="muted">：{{ g.names.slice(0, 3).join('、') }}<template v-if="g.names.length > 3"> 等</template></span>
            </div>
          </div>

          <details class="paste">
            <summary>也可以直接粘贴 YAML 文本</summary>
            <div class="field" style="margin-top: 8px">
              <textarea v-model="importer.text" class="textarea mono" rows="10" spellcheck="false"
                        placeholder="多份模板之间用一行 --- 分隔；这条通道按模板 id 命名"></textarea>
              <span class="field-hint">和文件能一起提交；格式不对的那一份只跳过自己</span>
            </div>
          </details>

          <div v-if="importer.result" class="stack" style="gap: 6px">
            <div class="tag ok" style="height: auto; padding: 4px 8px">
              成功导入 {{ importer.result.count }} 份<template v-if="(importer.result.failed || []).length">，失败 {{ importer.result.failed.length }} 份（失败的文件仍留在列表里，可修好后重试）</template>
            </div>
            <div v-for="(s, i) in (importer.result.saved || []).slice(0, 20)" :key="`s${i}`" class="tag"
                 style="height: auto; padding: 4px 8px; white-space: normal">
              {{ s.name }}<span class="muted"> · {{ s.id }}</span>
              <span v-if="s.overwritten" class="muted">（覆盖了同名旧模板）</span>
            </div>
            <div v-if="(importer.result.saved || []).length > 20" class="muted" style="font-size: 10.5px">
              只列出前 20 份，完整结果已写入模板库
            </div>
            <div v-for="(f, i) in importer.result.failed" :key="`f${i}`" class="tag err"
                 style="height: auto; padding: 4px 8px; white-space: normal">
              {{ f.file ? `${f.file} · ` : '' }}{{ f.head || '模板' }} · {{ f.error }}
            </div>
          </div>
        </div>
        <div class="modal-foot">
          <span class="muted mono" style="font-size: 10.5px; margin-right: auto">
            {{ importer.busy
              ? (importer.progress ? `正在导入 ${importer.progress.done}/${importer.progress.total} 个文件` : '正在导入…')
              : importer.reading ? '正在读取所选文件…'
              : importer.files.length ? `待导入 ${importer.files.length} 个文件${importer.skipped.length ? `，跳过 ${importer.skipped.length} 个` : ''}`
              : (importer.text.trim() ? '待导入粘贴内容' : '先选文件或粘贴内容') }}
          </span>
          <button class="btn sm" @click="importer.open = false">关闭</button>
          <button class="btn primary sm"
                  :disabled="importer.busy || importer.reading || (!importer.files.length && !importer.text.trim())"
                  @click="doImport">
            <Icon name="upload" :size="12" />{{ importer.busy
              ? (importer.progress ? `导入中 ${importer.progress.done}/${importer.progress.total}` : '导入中…')
              : importer.reading ? '读取中…'
              : (importer.files.length ? `导入 ${importer.files.length} 个文件` : '导入') }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.drop {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 6px;
  padding: 26px 18px;
  border: 1px dashed var(--line-strong);
  border-radius: var(--radius);
  background: var(--surface-2);
  color: var(--text-2);
  font-size: 12.5px;
  text-align: center;
  cursor: pointer;
  transition: border-color 0.15s, background 0.15s;
}
.drop:hover,
.drop.active {
  border-color: var(--cyan);
  background: var(--cyan-dim);
  color: var(--text);
}
.file-list {
  max-height: 190px;
  overflow: auto;
  border: 1px solid var(--line);
  border-radius: 8px;
}
.file-row {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 5px 9px;
  font-size: 11.5px;
  color: var(--text-2);
  border-bottom: 1px solid var(--line-soft);
}
.file-row:last-child {
  border-bottom: 0;
}
.skip-box {
  display: block;
  height: auto;
  padding: 6px 9px;
  white-space: normal;
  line-height: 1.6;
  max-height: 130px;
  overflow: auto;
}
.skip-line {
  font-size: 11px;
}
.paste summary {
  cursor: pointer;
  color: var(--muted);
  font-size: 11.5px;
  padding: 2px 0;
}
.paste summary:hover {
  color: var(--cyan-ink);
}
</style>
