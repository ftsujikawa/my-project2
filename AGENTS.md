# AGENTS.md(抜粋)
## Definition of Done
### required(全部 exit code 0 になるまで完了を宣言しない)
- pnpm typecheck
- pnpm test --run
- pnpm lint
### optional(失敗しても完了してよいが、結果を必ず報告する。再試行は 1 回まで)
- pnpm e2e
