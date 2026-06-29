## Summary

<!-- Кратко: что меняется и зачем -->

## Связанные issue

<!-- Обязательно для блокеров B1–B25: укажите Closes #NN или оставьте (Bn) в заголовке PR — issue закроется автоматически при merge (см. .github/workflows/close-blockers.yml). -->

- [ ] `Closes #NN` добавлено в описание **или** блокер указан в заголовке: `(B6)`
- Milestone / блокер: <!-- M1, B6, … -->

**Маппинг:** B*n* → issue #*(31+n)* (B6 → #37, B13 → #44).  
**B13 (NTLM):** auto-close только при `Closes #44` (полная реализация); docs-only PR не закрывают #44.

## Testing

<!-- cargo test, e2e, clippy — что запускали -->

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## Checklist

- [ ] CI зелёный
- [ ] Документация обновлена (если менялось поведение / env)
- [ ] `docs/BLOCKERS.md` / `docs/roadmap.md` (если закрывается блокер)
