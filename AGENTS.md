# AGENTS.md

## Code style
- Follow existing NestJS patterns in the repo.
- Group by feature/module: create a new folder per Haravan resource under `src/` (e.g. `haravan-product/`, `haravan-discount/`) with `*.controller.ts`, `*.service.ts`, `*.module.ts`, `dto/*.ts`.
- Do NOT create new files inside `src/haravan/` folder. The shared `HaravanOmniService` and `haravan.util.ts` remain there for reuse; do not add resource-specific controllers/services there.
- Keep controller routes under `haravan/:orgId/...` consistent with existing style.
- Use `forward()` from `HaravanOmniService` for proxying to Haravan API.
- Respect DTO validation with class-validator decorators.
