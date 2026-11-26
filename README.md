# HBF Alpha 1.4 R2 — YAML policy import/export (LAB PATCH)

**Основа:** Alpha 1.3 R2, прошедшая двухузловую лабораторную программу. Эта версия **меняет только контроллер и Web Console**, агенты v3, nftables, карантин, Ansible-регистрация, сохранённые политики и учётные записи сохраняются. Патч не является релизом для больничной production-сети.

## Изменения

- **Система → Импорт YAML / Экспорт YAML**. До подтверждения доступен серверный предпросмотр всех изменений по ID: `add`, `update`, `unchanged`, `remove`.
- `merge` (по умолчанию): новые `id` добавляются, существующие `id` обновляются, прочие политики сохраняются. `replace`: заменить весь набор политик. В режиме замены требуется ввести `REPLACE_POLICIES`, в режиме объединения `IMPORT_YAML`.
- Preview не меняет базу. Import меняет только базу SQLite **одной транзакцией**, создаёт ревизию и запись аудита. Для реального применения обязателен отдельный Plan/Diff и ручной Deploy.
- SHA256 отпечаток предпросмотра связан с текстом YAML, выбранным режимом и текущим набором политик; устаревшая предварительная проверка не может быть применена.
- Парсинг через PyYAML `SafeLoader` с запретом YAML aliases/anchors, нестандартных тегов, повторных ключей, лишних полей и множественных документов. Ограничение файла 1 МиБ, до 512 записей и суммарно до 512 политик.
- Каждая политика проверяется основным валидатором HBF (зарегистрированные хосты, диапазоны портов, CIDR, states, priorities, 22/8088, допустимые ICMP); комбинация политик проверяется на дублирование и конфликты на одинаковом приоритете. Ошибка в любом правиле отклоняет **весь** импорт.
- Прежние JSON импорт/экспорт, ручные формы, rollback и карантин оставлены без изменения.

## Корректировка старого примера

Источник: приложенный `пример правила.txt`.

- `HBF-001` (DROP TCP/8080, `kali01 → kali02`) сохраняется и принимается.
- `HBF-002` в оригинале пытался блокировать управляющий SSH/TCP22. Это запрещено HBF, независимо от `enabled`. В `examples/legacy-corrected.yaml` вместо него **отключённое** демонстрационное правило TCP/59022. Оно **не блокирует SSH**. Необходимо отдельно спроектировать управление, если для production нужен запрет SSH.
- `source`, `destination`, `protocol`, `destination_port`, `description` принимаются как старые имена; новые поля `family`, `ports`, `priority`, `states`, `src_cidrs`, `dst_cidrs`, `icmp_type`, `log_drop`, `tags`, `owner`, `ticket` также поддерживаются. `id` обязателен и является стабильным идентификатором для объединения. Если `enabled` пропущен, политика создаётся выключенной.
- Парсер не создаёт хосты из YAML: сначала зарегистрируйте их через Ansible, затем добавьте их в HBF Console.
- Существующие политики `P-...` сохраняют идентификаторы: YAML export → import обеспечивает повторную загрузку и обновление по тому же ID.

## Установка патча (Kali-1)

1. Snapshot обеих Kali; убедиться в статусе CLEAN, отсутствии карантина и `running`/`partial` Deploy.
2. Скопировать `hbf-alpha-1.4-r2.zip` в `/home/kali/Downloads/` на Kali-1.
3. Выполнить **единый блок**:

```bash
bash <<'BASH'
set -Eeuo pipefail
cd /home/kali
unzip -oq /home/kali/Downloads/hbf-alpha-1.4-r2.zip -d /home/kali
cd /home/kali/hbf-alpha-1.4-r2/bootstrap
ansible-playbook -i inventory.yml upgrade-1.4.yml -k -K
sudo systemctl is-active hbf-alpha-console.service
curl -fsS --max-time 5 -o /dev/null -w 'HTTP %{http_code}\n' http://127.0.0.1:8088/
ansible all -i inventory.yml -b -k -K -m shell -a '
  /usr/local/sbin/hbf-alpha-agent status
  nft -a list table inet hbf_alpha
  if nft list table inet hbf_quarantine >/dev/null 2>&1; then echo "WARNING: quarantine active"; exit 1; fi
'
echo 'ALPHA_1_4_PATCH_INSTALLED; NO DEPLOY EXECUTED'
BASH
```

4. Обновить браузер `Ctrl+Shift+R`, перейти в **Система → Импорт YAML**, выбрать `examples/legacy-corrected.yaml` (его можно скачать отдельно), режим `Добавить/обновить`, нажать **Проверить и показать изменения**. При подтверждении вводить `IMPORT_YAML`. Это сохраняет правила в базе, **но не запускает Deploy**.
5. Перед Deploy: посмотреть список политик, проверить Plan/Diff и Preflight; для первого теста желательно оставить новые правила `enabled: false` либо проводить в отдельной лабораторной сети. В примере HBF-001 активен и может обрубить TCP/8080 после Deploy.

## Совместимость и ограничения

- Импорт JSON из Alpha 1.3 работает по-прежнему и заменяет всё при подтверждении в старом UI. Для безопасного частичного добавления используйте новый YAML `merge`.
- `ACCEPT` в таблице HBF с `policy accept` **не** означает default-deny, не обходит других firewall. `QUARANTINE` работает независимо.
- VLAN в YAML — это **не** VLAN enforcement. Правила требуют зарегистрированных серверов. Не следует использовать YAML-пример для управления целыми VLAN и внутрикластерным L2 без соответствующих агентов/маршрутизаторов.
- Служба `hbf-alpha-console.service` перезапускается в ходе upgrade; действующие nftables на хостах не меняются. Резервная копия предыдущего каталога контроллера создаётся в `/var/backups/hbf-alpha/controller-pre-1.4` (при первом запуске playbook).
- Зависимость `PyYAML` ставится только в venv контроллера. Для тестов в отдельном test-окружении нужны FastAPI, PyYAML и совместимый `httpx`/`httpx2` в зависимости от Starlette.

## Разработчикам

```bash
PYTHONPATH=controller PYTHONWARNINGS=ignore::DeprecationWarning python3 -m unittest discover -s tests -q
node --check controller/static/app.js
node tests/test_topology.js
python3 -m py_compile controller/app.py controller/yaml_io.py agent/hbf-alpha-agent
```

**Не подтверждено до реальной установки на Kali:** совместимость с системой пакетов Kali-1, работа кнопок YAML в реальном браузере, импорт/экспорт через UI и сохранность политики после обновления. Тесты разработчика в изолированной среде не равны интеграционным испытаниям на Kali.

## Откат к прежнему контроллеру (при необходимости)

При неуспешном обновлении или проблемах нового UI, **после проверки отсутствия running/partial Deploy**, на Kali-1 выполнить одну команду:

```bash
cd /home/kali/hbf-alpha-1.4-r2/bootstrap && ansible-playbook -i inventory.yml rollback-1.4.yml -k -K
```

Откат восстанавливает резервную копию исходников контроллера и перезапускает службу. Он **не изменяет nftables, агентов и базу SQLite**. В частности, YAML-политики, уже импортированные в БД, останутся и будут видны старому контроллеру как обычные политики.
