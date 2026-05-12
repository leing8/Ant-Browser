import {Link} from 'react-router-dom'
import {ExternalLink, XCircle} from 'lucide-react'
import {Button, FormItem, Input, Modal} from '../../../../shared/components'
import {KeywordsModal} from '../../components/KeywordsModal'
import type {BrowserProfile} from '../../types'

interface BrowserListDialogsProps {
  proxyErrorModal: boolean
  pendingStartId: string | null
  proxyErrorMsg: string
  onCloseProxyError: () => void
  onStartDirect: () => void
  startingDirect: boolean
  kwModal: { open: boolean; profile: BrowserProfile | null }
  onCloseKeywords: () => void
  onKeywordsSaved: (keywords: string[]) => void
  expandModalOpen: boolean
  onCloseExpand: () => void
  profilesCount: number
  maxProfileLimit: number
  cdKey: string
  onCdKeyChange: (value: string) => void
  onRedeem: () => void
  redeeming: boolean
  onOpenGithubStarGift: () => void
  copyModal: { open: boolean; profile: BrowserProfile | null }
  copyName: string
  copyCount: number
  onCopyNameChange: (value: string) => void
  onCopyCountChange: (value: number) => void
  onCloseCopy: () => void
  onConfirmCopy: () => void
  copying: boolean
  opError: string
  onCloseOpError: () => void
}

export function BrowserListDialogs({
  proxyErrorModal,
  pendingStartId,
  proxyErrorMsg,
  onCloseProxyError,
  onStartDirect,
  startingDirect,
  kwModal,
  onCloseKeywords,
  onKeywordsSaved,
  expandModalOpen,
  onCloseExpand,
  profilesCount,
  maxProfileLimit,
  cdKey,
  onCdKeyChange,
  onRedeem,
  redeeming,
  onOpenGithubStarGift,
  copyModal,
  copyName,
  copyCount,
  onCopyNameChange,
  onCopyCountChange,
  onCloseCopy,
  onConfirmCopy,
  copying,
  opError,
  onCloseOpError,
}: BrowserListDialogsProps) {
  return (
    <>
      <Modal
        open={proxyErrorModal}
        onClose={onCloseProxyError}
        title="代理链路不可用"
        width="420px"
        footer={
          <>
            <Button variant="secondary" onClick={onCloseProxyError} disabled={startingDirect}>取消</Button>
            {pendingStartId && (
              <Button variant="secondary" onClick={onStartDirect} loading={startingDirect}>
                直连启动
              </Button>
            )}
            {pendingStartId && (
              <Link to={`/browser/edit/${pendingStartId}`}>
                <Button onClick={onCloseProxyError} disabled={startingDirect}>去修改代理</Button>
              </Link>
            )}
          </>
        }
      >
        <div className="space-y-3">
          <div className="flex items-start gap-3 p-3 rounded-lg bg-[var(--color-bg-secondary)]">
            <XCircle className="w-5 h-5 text-red-500 mt-0.5 shrink-0" />
            <p className="text-sm text-[var(--color-text-primary)]">{proxyErrorMsg}</p>
          </div>
          <p className="text-sm text-[var(--color-text-muted)]">请前往编辑页面重新选择可用链路；如果是订阅导入，先刷新订阅并确认该节点仍存在。</p>
        </div>
      </Modal>

      {kwModal.profile && (
        <KeywordsModal
          open={kwModal.open}
          profileId={kwModal.profile.profileId}
          profileName={kwModal.profile.profileName}
          initialKeywords={kwModal.profile.keywords || []}
          onClose={onCloseKeywords}
          onSaved={onKeywordsSaved}
        />
      )}

      <Modal
        open={expandModalOpen}
        onClose={onCloseExpand}
        title="实例扩容系统"
        width="480px"
        footer={<Button variant="secondary" onClick={onCloseExpand}>关闭</Button>}
      >
        <div className="space-y-4">
          <div className="bg-[var(--color-bg-secondary)] p-4 rounded-lg flex items-center justify-between border border-[var(--color-border-default)]">
            <div>
              <p className="text-sm font-medium text-[var(--color-text-primary)]">当前使用情况</p>
              <p className="text-xs text-[var(--color-text-muted)] mt-1">每个配置都需要消耗 1 个实例额度</p>
            </div>
            <div className="text-right">
              <span className={`text-2xl font-semibold ${profilesCount >= maxProfileLimit ? 'text-red-500' : 'text-[var(--color-success)]'}`}>
                {profilesCount}
              </span>
              <span className="text-sm text-[var(--color-text-muted)] ml-1">/ {maxProfileLimit}</span>
            </div>
          </div>

          <div className="pt-2 border-t border-[var(--color-border-muted)]">
            <label className="block text-sm font-medium text-[var(--color-text-primary)] mb-2">使用兑换码扩容</label>
            <div className="flex gap-2">
              <Input
                value={cdKey}
                onChange={e => onCdKeyChange(e.target.value)}
                placeholder="输入兑换码 (如 ANT-...)"
                onKeyDown={e => e.key === 'Enter' && onRedeem()}
                className="flex-1"
              />
              <Button onClick={onRedeem} loading={redeeming} disabled={!cdKey.trim()}>
                进行兑换
              </Button>
            </div>
          </div>

          <div className="mt-4 p-3 bg-blue-500/10 border border-blue-500/20 rounded-lg">
            <div className="flex items-center justify-between gap-4">
              <p className="text-sm text-[var(--color-text-primary)]">点亮 GitHub Star 后，可再获赠 50 个永久额度</p>
              <button
                type="button"
                className="shrink-0 rounded-full p-2 text-[var(--color-accent)] transition-colors hover:bg-[var(--color-accent)]/10 disabled:opacity-50"
                onClick={onOpenGithubStarGift}
                disabled={redeeming}
                title="打开 GitHub 并领取赠送"
                aria-label="打开 GitHub 并领取赠送"
              >
                <ExternalLink className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      </Modal>

      <Modal
        open={copyModal.open}
        onClose={onCloseCopy}
        title="复制实例"
        width="420px"
        footer={
          <>
            <Button variant="secondary" onClick={onCloseCopy}>取消</Button>
            <Button onClick={onConfirmCopy} loading={copying}>确认复制</Button>
          </>
        }
      >
        <div className="space-y-4">
          <p className="text-sm text-[var(--color-text-muted)]">
            复制实例将保留原有的代理、内核、启动参数、标签、指纹配置等，但会生成新的指纹种子以确保每个副本拥有独立的指纹特征。
          </p>
          <FormItem label="新实例名称" required>
            <Input
              value={copyName}
              onChange={e => onCopyNameChange(e.target.value)}
              placeholder="请输入新实例名称"
              autoFocus
            />
          </FormItem>
          <FormItem label="复制数量" hint={copyCount > 1 ? `将自动以 "名称_1, 名称_2, ..." 方式命名` : undefined}>
            <Input
              type="number"
              value={String(copyCount)}
              onChange={e => {
                const v = parseInt(e.target.value, 10)
                onCopyCountChange(isNaN(v) ? 1 : Math.max(1, Math.min(100, v)))
              }}
              min={1}
              max={100}
              placeholder="1"
            />
          </FormItem>
        </div>
      </Modal>

      <Modal
        open={!!opError}
        onClose={onCloseOpError}
        title="操作失败"
        width="420px"
        footer={<Button onClick={onCloseOpError}>知道了</Button>}
      >
        <div className="text-[var(--color-text-secondary)] whitespace-pre-line">{opError}</div>
      </Modal>
    </>
  )
}
