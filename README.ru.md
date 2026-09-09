# web-audit-pro

[![CI](https://github.com/HackToolWork/web-audit-pro/actions/workflows/ci.yml/badge.svg)](https://github.com/HackToolWork/web-audit-pro/actions/workflows/ci.yml)
[![CodeQL](https://github.com/HackToolWork/web-audit-pro/actions/workflows/codeql.yml/badge.svg)](https://github.com/HackToolWork/web-audit-pro/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Security](https://img.shields.io/badge/security-responsible%20use-green.svg)](SECURITY.md)

[English](README.md) **| Русский**

> **Web Audit Pro — низконагруженный и аудируемый набор инструментов для авторизованной оценки безопасности веб-систем, security engineering и bug-bounty triage.**

Проект объединяет детерминированные HTTP-проверки, пассивный DNS- и JavaScript-анализ, fingerprinting CMS, локальное обогащение данными об уязвимостях, контроль scope, rate limiting, историю сканирований, воспроизводимые отчёты, SARIF, опциональный TUI и локальную read-only web-панель.

**Используйте программу только на системах, которыми вы владеете или которые вам явно разрешено проверять.** Флаг авторизации — подтверждение пользователя, а не юридическое разрешение.

---

## За 60 секунд до первого запуска

### Kali Linux / Debian / Ubuntu

```bash
git clone https://github.com/HackToolWork/web-audit-pro.git
cd web-audit-pro
sudo ./install.sh
web-audit example.com --yes-i-am-authorized
```

### Docker

```bash
docker build -t web-audit-pro:local .
mkdir -p reports
docker run --rm \\
  -u "$(id -u):$(id -g)" \\
  -v "$PWD/reports:/app/reports" \\
  web-audit-pro:local example.com --yes-i-am-authorized
```

### Windows / macOS / другие Python-окружения

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
web-audit example.com --yes-i-am-authorized
```

Для разработки используйте `make install-dev` и `make check`.

---

## Зачем создан проект

Веб-безопасность часто оказывается между двумя крайностями: маленькими одноразовыми скриптами с хрупким выводом и тяжёлыми сканерами, которые сложно аудировать и легко запустить слишком агрессивно.

Web Audit Pro сознательно занимает промежуточное положение:

- **Низкое воздействие:** консервативная скорость запросов, ограничение размера ответов, GET-only логика оценки и отсутствие автоматического takeover/exploit delivery.
- **Аудируемость:** каждая находка содержит rule ID, severity, evidence, confidence и remediation.
- **Автоматизация:** стабильные JSON/CSV/HTML/SARIF/SQLite-результаты подходят для CI, cron, контейнеров и локального анализа.
- **Переносимость:** в коде нет путей конкретного разработчика; конфигурация и кэш используют переносимые пользовательские каталоги.
- **Работа офлайн:** CMS/CVE-обогащение можно выполнять через локальную advisory-базу после явного обновления.
- **Контроль scope:** private targets, поиск поддоменов и собственные списки путей являются явными и управляемыми режимами.

Любая находка — это **сигнал для ручной проверки**, а не автоматическое доказательство возможности эксплуатации.

---

## Возможности

| Область | Возможность | По умолчанию |
|---|---|---|
| HTTP | Статус, задержка, размер ответа, redirect, ошибки запросов | Включено |
| Заголовки | HSTS, CSP, `nosniff`, Referrer-Policy, защита от clickjacking | Включено |
| Cookies | `Secure`, `HttpOnly`, `SameSite`, небезопасный `SameSite=None` | Включено |
| CORS | Комбинации wildcard / credentials | Включено |
| Disclosure | `Server`, `X-Powered-By` | Включено |
| JavaScript | Поиск credential-like значений с редактированием секретов | Опционально (`--scan-js`) |
| DNS | A/AAAA, MX, TXT, SPF, CNAME | Опционально / через config |
| CMS | Fingerprinting и advisory references | Опционально / через config |
| Vulnerability DB | Локальный поиск CVE/advisory | После `--update-db` |
| Поддомены | Кандидаты из Certificate Transparency | Опционально (`--discover-subdomains`) |
| История | Сравнение сканирований | Доступно |
| Отчёты | HTML, JSON, CSV, SARIF, SQLite | Доступно |
| TUI | Живой progress и high-severity alerts | Опционально (`--tui`) |
| Dashboard | Локальная read-only web-панель | Опционально (`--serve`) |

---

## Типовые сценарии

### 1. Обычный авторизованный аудит

```bash
web-audit example.com --yes-i-am-authorized
```

### 2. Пассивный анализ JavaScript

```bash
web-audit example.com \\
  --yes-i-am-authorized \\
  --scan-js
```

JavaScript-находки не сохраняют секреты в открытом виде: чувствительные значения редактируются в evidence. Модуль предназначен для обнаружения credential-like материала, который затем должен быть вручную проверен и, при необходимости, отозван.

### 3. Пассивный инвентарь поддоменов

```bash
web-audit example.com \\
  --yes-i-am-authorized \\
  --discover-subdomains
```

Certificate Transparency рассматривается только как источник кандидатов. Найденное имя не означает, что хост жив, доступен или находится в разрешённом scope.

### 4. CMS + офлайн advisory enrichment

Сначала обновите локальную базу:

```bash
web-audit --update-db
```

Затем используйте её в аудите:

```bash
web-audit example.com \\
  --yes-i-am-authorized \\
  --cms-vuln-lookup
```

Обычный аудит не обращается к NVD только потому, что включено CMS-обогащение.

### 5. Внутренняя лаборатория

Для private/loopback и других не-public targets в явно авторизованной лаборатории:

```bash
web-audit internal.example \\
  --yes-i-am-authorized \\
  --allow-private
```

### 6. CI gate

```bash
web-audit example.com \\
  --yes-i-am-authorized \\
  --fail-on medium
```

### 7. Автоматически открыть HTML-отчёт

```bash
web-audit example.com \\
  --yes-i-am-authorized \\
  --open
```

### 8. Локальная web-панель

```bash
web-audit example.com \\
  --yes-i-am-authorized \\
  --serve
```

Панель предназначена для локального или явно контролируемого окружения и работает в режиме чтения.

---

## Конфигурация

Web Audit Pro поддерживает TOML-конфигурацию, чтобы повторяющиеся параметры не приходилось вводить вручную при каждом запуске.

Создайте свою конфигурацию из шаблона:

```bash
cp web-audit.toml.example web-audit.toml
```

### Приоритет настроек

```text
CLI > TOML > встроенные значения
```

Явный параметр командной строки всегда имеет приоритет.

### Минимальный пример

```toml
[scan]
threads = 10
requests_per_second = 2.0
timeout = 5.0
output_dir = "reports"

[features]
dns = true
cms = true
scan_js = true
tui = false

[report]
company = "Security Assessment Team"
theme = "dark"

[nvd]
nvd_timeout = 12.0
```

В шаблоне специально указано нейтральное название компании. Для своих отчётов замените его на нужное.

### Где ищется конфигурация

Проект может использовать локальный TOML в каталоге проекта или стандартный пользовательский каталог конфигурации. Для детерминированного выбора используйте `--config /path/to/file.toml`.

Относительные пути разрешаются в контексте конфигурации, а не относительно каталога конкретного разработчика.

---

## Контроль scope

Контроль scope — базовая функция безопасности, а не декоративная опция.

Пример:

```text
example.com
*.example.com
```

Запуск:

```bash
web-audit example.com \\
  --yes-i-am-authorized \\
  --scope-file examples/scope.txt
```

Для bug-bounty сохраняйте копию письменных правил программы рядом с конфигурацией и переводите в scope-файл только действительно разрешённые хосты.

---

## Пути и словари

Можно передать собственный список путей:

```bash
web-audit example.com \\
  --yes-i-am-authorized \\
  --paths-file examples/paths.txt
```

На системах с подходящими security wordlists можно явно включить их поиск:

```bash
web-audit example.com \\
  --yes-i-am-authorized \\
  --kali-wordlist
```

Kali-словарь не является обязательным. При его отсутствии проект безопасно возвращается к встроенному набору путей.

---

## Отчёты

Сканер умеет создавать:

- **HTML** — для людей и клиентского review;
- **JSON** — для автоматизации и сравнения сканов;
- **CSV** — для таблиц и triage;
- **SARIF 2.1.0** — для security tooling и CI-интеграций;
- **SQLite** — для локальной истории и dashboard.

По умолчанию имена файлов содержат идентификатор запуска, поэтому параллельные контейнеры не перетирают друг друга.

### Сравнение двух сканов

```bash
web-audit example.com \\
  --yes-i-am-authorized \\
  --compare reports/previous.json
```

### SARIF в CI

SARIF предназначен для машинно-читаемых результатов и интеграции с поддерживающими его security-инструментами. Формат ориентирован на доказательства и триаж: наличие результата не означает, что эксплуатация выполнялась.

---

## База уязвимостей

Работа с advisory-базой намеренно разделена на две операции:

```text
web-audit --update-db
        ↓
локальная advisory-база
        ↓
web-audit ... --cms-vuln-lookup
```

Так обычный аудит не зависит от доступности внешнего vulnerability API.

Путь к базе можно переопределить:

```bash
export WEB_AUDIT_VULN_DB=/path/to/vulndb.sqlite3
```

В поставляемом Docker-образе используется `/app/reports/vulndb.sqlite3`, чтобы база сохранялась в примонтированном каталоге.

---

## Docker

Образ собирается в несколько стадий и запускается без root-привилегий.

Для постоянного хранения отчётов и локальной advisory-базы:

```bash
mkdir -p reports
docker run --rm \\
  -u "$(id -u):$(id -g)" \\
  -v "$PWD/reports:/app/reports" \\
  web-audit-pro:local --help
```

При параллельном запуске контейнеров в одном output-каталоге имена отчётов по умолчанию уникальны. Для SQLite-записи используется ограниченная стратегия блокировки, а обычные advisory lookup выполняются в read-only режиме.

---

## Разработка

Рекомендуемый workflow:

```bash
make install-dev
make check
```

`make` уважает уже активное `VIRTUAL_ENV`. Если активного окружения нет, при необходимости создаётся локальный `.venv` в репозитории.

Полезные цели:

```text
make test
make lint
make compile
make check
make build
make docker-build
make clean
```

Если в активном окружении разработчика нет нужного инструмента, например `pytest`, Makefile сообщает точную команду установки и не заменяет окружение молча.

---

## Структура проекта

```text
web-audit-pro/
├── .github/              # CI, CodeQL, Dependabot, issue/PR templates
├── examples/             # примеры scope/path/target-файлов
├── tests/                # unit и integration tests
├── web_audit/            # пакет приложения
│   ├── data/              # данные fingerprint CMS
│   ├── scanner.py         # HTTP-движок сканирования
│   ├── dns_audit.py       # пассивный DNS-анализ
│   ├── js_audit.py        # пассивный JavaScript-анализ
│   ├── cms.py             # fingerprinting CMS
│   ├── vulndb.py          # локальная advisory DB
│   ├── nvd.py             # явное обновление advisory DB
│   ├── reports.py         # HTML/JSON/CSV
│   ├── sarif.py           # SARIF output
│   ├── serve.py            # read-only dashboard
│   └── tui.py              # terminal UI
├── Dockerfile
├── Makefile
├── install.sh
├── pyproject.toml
├── requirements.txt
├── requirements-dev.txt
├── web-audit.toml.example
├── SECURITY.md
├── CONTRIBUTING.md
└── LICENSE
```

---

## Ответственное использование

Web Audit Pro предназначен для авторизованной работы.

В проект намеренно не входят:

- атаки на учётные данные и password spraying;
- brute-force аутентификация;
- доставка exploit payloads;
- destructive requests;
- unrestricted crawling;
- автоматические попытки захвата стороннего сервиса;
- stealth-функции для обхода механизмов контроля доступа.

Перед тестированием публичной программы изучите её правила, определите точные in-scope хосты, соблюдайте rate limits и собирайте достаточно evidence для воспроизведения проблемы без ненужного раскрытия секретов.

Политика безопасности: [SECURITY.md](SECURITY.md).

---

## Модель угроз и ограничения

Web Audit Pro — это **инструмент низконагруженного аудита и triage**, а не полная замена penetration testing.

Он не гарантирует обнаружение уязвимости, эксплуатацию, бизнес-влияние или соответствие конкретной bug-bounty программе. WAF, аутентификация, состояние приложения, сетевые ограничения и правила scope влияют на результаты наблюдений.

Перед публикацией находки, исправлением или отправкой в bug-bounty её необходимо вручную проверить.

---

## Вклад в проект

Вклады приветствуются.

Перед Pull Request выполните:

```bash
make install-dev
make check
```

Старайтесь держать изменения сфокусированными, добавляйте regression tests для исправлений, не добавляйте пути конкретного разработчика и сохраняйте low-impact/scope-aware модель проекта.

Документы:

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- [SECURITY.md](SECURITY.md)

---

## Процесс релиза

Релизы используют аннотированные Git-теги формата:

```text
vX.Y.Z
```

Release workflow проверяет соответствие тега версии пакета, устанавливает pinned developer toolchain, запускает lint и тесты, собирает Python-дистрибутивы, создаёт SHA-256 checksums и публикует assets релиза.

Репозиторий также запускает CodeQL и dependency review через GitHub Actions.

---

## Поддержка и сообщество

- **Репозиторий:** https://github.com/HackToolWork/web-audit-pro
- **Безопасность:** [SECURITY.md](SECURITY.md)
- **Разработка:** [CONTRIBUTING.md](CONTRIBUTING.md)
- **Поддержка:** [SUPPORT.md](SUPPORT.md)
- **Лицензия:** [Apache-2.0](LICENSE)

### Поддержка проекта

Web Audit Pro — open-source проект. Спонсорская поддержка может помогать финансировать сопровождение, документацию, исследования безопасности, тестирование и новые защитные возможности.

---

## Лицензия

Web Audit Pro распространяется по **Apache License 2.0**.

См. [LICENSE](LICENSE).
