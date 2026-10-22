import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { Network, ShieldCheck } from 'lucide-react'
import ImageTrustConsole from './ImageTrustConsole'
import './styles.css'
import './trust-standalone.css'

// No Snapshot/demo API is loaded by this entry. All observations originate in
// the protected, same-origin candidate API after an explicit user connection.
createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <header className="trust-frame-header">
      <div><Network aria-hidden="true" size={23} /><strong>澄网</strong><span>可信控制面</span></div>
      <span><ShieldCheck aria-hidden="true" size={16} />隔离候选 · 未发布</span>
    </header>
    <main className="trust-frame-main"><ImageTrustConsole /></main>
    <footer className="trust-frame-footer">只读观察，不执行设备变更。测试通过不等于生产上线。</footer>
  </StrictMode>,
)
