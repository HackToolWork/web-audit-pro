"""Plain-language explanations of findings for non-technical site owners.

Each entry maps a rule ID to ``(title, why it matters, what to do)`` per language.
Texts must stay accurate and calm: they explain business impact without
overstating risk, and the action is phrased so it can be forwarded to a
developer or hosting provider as-is.
"""

from __future__ import annotations

LANGUAGES = ("en", "ru")

RuleText = tuple[str, str, str]

_ANY_DEVELOPER_RU = "Передайте эту задачу разработчику сайта или в поддержку хостинга."
_ANY_DEVELOPER_EN = "Forward this task to your site developer or hosting support."

RULE_TEXTS: dict[str, dict[str, RuleText]] = {
    "tls.certificate_expired": {
        "ru": (
            "SSL-сертификат сайта истёк",
            "Браузеры показывают посетителям предупреждение «Подключение не защищено». "
            "Большинство людей уходят с такого сайта, а платежи и формы могут перестать работать.",
            "Срочно продлите сертификат и включите автоматическое продление "
            "(например, Let's Encrypt в панели хостинга).",
        ),
        "en": (
            "The site's SSL certificate has expired",
            "Browsers show visitors a 'connection is not secure' warning. Most people leave, "
            "and payments or forms may stop working.",
            "Renew the certificate now and enable automatic renewal "
            "(for example, Let's Encrypt in your hosting panel).",
        ),
    },
    "tls.certificate_invalid": {
        "ru": (
            "Браузеры не доверяют SSL-сертификату сайта",
            "Посетители видят предупреждение безопасности вместо сайта. Обычно причина в том, "
            "что сертификат выпущен на другой адрес или установлен не полностью.",
            "Установите корректный сертификат для этого домена (включая промежуточные "
            f"сертификаты). {_ANY_DEVELOPER_RU}",
        ),
        "en": (
            "Browsers do not trust the site's SSL certificate",
            "Visitors see a security warning instead of the site. Usually the certificate was "
            "issued for another address or installed incompletely.",
            "Install a valid certificate for this domain, including intermediate certificates. "
            f"{_ANY_DEVELOPER_EN}",
        ),
    },
    "tls.certificate_expiring": {
        "ru": (
            "SSL-сертификат скоро истечёт",
            "После окончания срока браузеры начнут предупреждать посетителей, что сайт "
            "небезопасен.",
            "Продлите сертификат заранее и проверьте, что автоматическое продление работает.",
        ),
        "en": (
            "The SSL certificate expires soon",
            "Once it expires, browsers will warn visitors that the site is not secure.",
            "Renew the certificate in advance and confirm that automatic renewal works.",
        ),
    },
    "dns.dmarc.missing": {
        "ru": (
            "Почта домена не защищена от подделки (нет DMARC)",
            "Мошенники могут рассылать письма от имени вашего домена, например поддельные "
            "счета клиентам. Кроме того, ваши настоящие письма чаще попадают в спам.",
            "Добавьте в DNS запись DMARC: начните с режима наблюдения (p=none) с адресом для "
            "отчётов, затем переходите к p=quarantine или p=reject. Это делается в панели "
            "регистратора или DNS-хостинга.",
        ),
        "en": (
            "Your domain's email is not protected from spoofing (no DMARC)",
            "Fraudsters can send email that appears to come from your domain, such as fake "
            "invoices to customers. Your real emails are also more likely to land in spam.",
            "Add a DMARC DNS record: start in monitoring mode (p=none) with a reporting address, "
            "then move to p=quarantine or p=reject. This is done in your DNS provider's panel.",
        ),
    },
    "dns.dmarc.multiple": {
        "ru": (
            "Несколько записей DMARC — защита почты не работает",
            "Когда записей DMARC несколько, почтовые сервисы игнорируют их все, и домен "
            "остаётся без защиты от поддельных писем.",
            "Оставьте в DNS одну запись DMARC.",
        ),
        "en": (
            "Multiple DMARC records — email protection is not working",
            "When several DMARC records exist, mail providers ignore all of them and the domain "
            "is left without spoofing protection.",
            "Keep exactly one DMARC record in DNS.",
        ),
    },
    "dns.dmarc.invalid_policy": {
        "ru": (
            "Запись DMARC настроена с ошибкой",
            "В записи нет корректного правила p=, поэтому почтовые сервисы не знают, что делать "
            "с поддельными письмами.",
            "Исправьте запись DMARC: укажите p=none, p=quarantine или p=reject.",
        ),
        "en": (
            "The DMARC record is misconfigured",
            "The record has no valid p= policy, so mail providers do not know what to do with "
            "spoofed email.",
            "Fix the DMARC record: set p=none, p=quarantine, or p=reject.",
        ),
    },
    "dns.dmarc.monitor_only": {
        "ru": (
            "DMARC только наблюдает, но не блокирует поддельные письма",
            "Режим p=none полезен на старте, но поддельные письма от вашего имени всё ещё "
            "доставляются получателям.",
            "Изучите отчёты DMARC и, убедившись, что вся ваша настоящая почта проходит проверку, "
            "переключитесь на p=quarantine или p=reject.",
        ),
        "en": (
            "DMARC only monitors and does not block spoofed email",
            "p=none is a good start, but spoofed email in your name is still delivered.",
            "Review DMARC reports and, once all your legitimate mail passes, switch to "
            "p=quarantine or p=reject.",
        ),
    },
    "dns.spf.missing": {
        "ru": (
            "Не найдена запись SPF для почты",
            "SPF сообщает почтовым сервисам, какие серверы могут отправлять письма от вашего "
            "имени. Без неё письма чаще попадают в спам, а подделать отправителя проще.",
            "Если с домена отправляется почта, добавьте запись SPF со списком ваших почтовых "
            "сервисов (подсказку даёт почтовый провайдер).",
        ),
        "en": (
            "No SPF record found for email",
            "SPF tells mail providers which servers may send email for your domain. Without it, "
            "mail lands in spam more often and spoofing is easier.",
            "If the domain sends email, add an SPF record listing your mail services "
            "(your email provider documents the exact value).",
        ),
    },
    "dns.spf.multiple": {
        "ru": (
            "Несколько записей SPF — проверка почты ломается",
            "При нескольких записях SPF проверка завершается ошибкой, и ваши письма могут "
            "отклоняться или попадать в спам.",
            "Объедините записи в одну запись SPF.",
        ),
        "en": (
            "Multiple SPF records break email checks",
            "With several SPF records the check fails, so your email may be rejected or "
            "marked as spam.",
            "Merge them into a single SPF record.",
        ),
    },
    "dns.spf.permissive_all": {
        "ru": (
            "SPF разрешает отправлять почту от вашего имени кому угодно",
            "Правило +all фактически отключает защиту: любой сервер в интернете считается "
            "разрешённым отправителем.",
            "Замените +all на -all или ~all и перечислите только ваши почтовые сервисы.",
        ),
        "en": (
            "SPF allows anyone to send email in your name",
            "The +all rule effectively disables protection: any server on the internet counts "
            "as an authorized sender.",
            "Replace +all with -all or ~all and list only your mail services.",
        ),
    },
    "dns.spf.neutral_all": {
        "ru": (
            "SPF не запрещает посторонним отправлять почту",
            "Правило ?all не просит почтовые сервисы отклонять письма от посторонних серверов.",
            "Когда список ваших почтовых сервисов в SPF полный, замените ?all на ~all или -all.",
        ),
        "en": (
            "SPF does not reject unknown senders",
            "The ?all rule does not ask mail providers to reject email from other servers.",
            "Once your SPF lists all your mail services, replace ?all with ~all or -all.",
        ),
    },
    "dns.cname.potential_takeover": {
        "ru": (
            "Поддомен указывает на неиспользуемый внешний сервис",
            "Если сервис больше не ваш, посторонний может занять его и разместить свой контент "
            "на вашем поддомене. Это требует ручной проверки.",
            "Проверьте, используется ли ещё этот сервис; если нет — удалите DNS-запись.",
        ),
        "en": (
            "A subdomain points to an unused external service",
            "If the service is no longer yours, someone else could claim it and publish content "
            "on your subdomain. This needs manual confirmation.",
            "Check whether the service is still in use; if not, remove the DNS record.",
        ),
    },
    "headers.hsts": {
        "ru": (
            "Браузерам не запрещено открывать сайт без шифрования",
            "Без заголовка HSTS в публичных Wi-Fi-сетях посетителя можно незаметно перевести на "
            "незащищённую версию сайта.",
            f"Включите заголовок Strict-Transport-Security. {_ANY_DEVELOPER_RU}",
        ),
        "en": (
            "Browsers are not required to use encryption",
            "Without the HSTS header, visitors on public Wi-Fi can be silently moved to an "
            "unencrypted version of the site.",
            f"Enable the Strict-Transport-Security header. {_ANY_DEVELOPER_EN}",
        ),
    },
    "headers.hsts_disabled": {
        "ru": (
            "Защита HSTS явно отключена",
            "Сайт сообщает браузерам не запоминать требование шифрования (max-age=0), поэтому "
            "защита не действует.",
            f"Установите в Strict-Transport-Security положительный max-age. {_ANY_DEVELOPER_RU}",
        ),
        "en": (
            "HSTS protection is explicitly disabled",
            "The site tells browsers not to remember the encryption requirement (max-age=0), so "
            "the protection is off.",
            f"Set a positive max-age in Strict-Transport-Security. {_ANY_DEVELOPER_EN}",
        ),
    },
    "headers.content_type_options": {
        "ru": (
            "Не включена защита от подмены типа файлов",
            "Это небольшая дополнительная защита браузера от некоторых атак через загруженные "
            "файлы.",
            f"Добавьте заголовок X-Content-Type-Options: nosniff. {_ANY_DEVELOPER_RU}",
        ),
        "en": (
            "File-type sniffing protection is not enabled",
            "A small extra browser safeguard against some attacks that use uploaded files.",
            f"Add the X-Content-Type-Options: nosniff header. {_ANY_DEVELOPER_EN}",
        ),
    },
    "headers.csp": {
        "ru": (
            "Нет политики безопасности контента (CSP)",
            "CSP ограничивает, какие скрипты может запускать страница, и снижает ущерб, если на "
            "сайт внедрят вредоносный код.",
            "Разработчику: внедрить Content-Security-Policy, начав с режима Report-Only, чтобы "
            "ничего не сломать.",
        ),
        "en": (
            "No Content Security Policy (CSP)",
            "CSP limits which scripts a page may run and reduces the damage if malicious code "
            "is injected into the site.",
            "For your developer: introduce a Content-Security-Policy, starting in Report-Only "
            "mode so nothing breaks.",
        ),
    },
    "headers.csp_report_only": {
        "ru": (
            "Политика CSP работает только в режиме наблюдения",
            "Нарушения записываются в отчёты, но не блокируются.",
            "Когда отчёты перестанут показывать ложные срабатывания, включите политику в "
            "обязательном режиме.",
        ),
        "en": (
            "CSP runs in report-only mode",
            "Violations are reported but not blocked.",
            "Once reports show no false positives, switch the policy to enforcing mode.",
        ),
    },
    "headers.referrer_policy": {
        "ru": (
            "Не задано, какие адреса страниц передаются другим сайтам",
            "При переходе по ссылкам внешние сайты могут видеть полные адреса ваших страниц, "
            "включая параметры.",
            f"Добавьте заголовок Referrer-Policy (например, strict-origin-when-cross-origin). "
            f"{_ANY_DEVELOPER_RU}",
        ),
        "en": (
            "Referrer policy is not set",
            "When visitors follow links, other sites may see the full addresses of your pages, "
            "including parameters.",
            "Add a Referrer-Policy header (for example, strict-origin-when-cross-origin). "
            f"{_ANY_DEVELOPER_EN}",
        ),
    },
    "headers.clickjacking": {
        "ru": (
            "Сайт можно встроить в чужую страницу",
            "Злоумышленник может показать ваш сайт внутри своей страницы и обманом заставить "
            "посетителя нажать нужную ему кнопку.",
            "Запретите встраивание: CSP frame-ancestors 'self' или X-Frame-Options: SAMEORIGIN. "
            f"{_ANY_DEVELOPER_RU}",
        ),
        "en": (
            "The site can be embedded in other pages",
            "An attacker can show your site inside their own page and trick visitors into "
            "clicking buttons for them.",
            "Block embedding with CSP frame-ancestors 'self' or X-Frame-Options: SAMEORIGIN. "
            f"{_ANY_DEVELOPER_EN}",
        ),
    },
    "cors.wildcard_credentials": {
        "ru": (
            "Опасная настройка доступа для других сайтов (CORS)",
            "Настройка разрешает любым сайтам обращаться к вашему сайту и одновременно "
            "передавать данные входа. Это требует проверки разработчиком.",
            "Разрешите доступ только конкретным доверенным адресам.",
        ),
        "en": (
            "Risky cross-site access setting (CORS)",
            "The configuration lets any website access your site while also sending login "
            "data. A developer should review it.",
            "Allow access only for specific trusted origins.",
        ),
    },
    "cookies.secure": {
        "ru": (
            "Cookies могут передаваться без шифрования",
            "Если cookie отвечает за вход в аккаунт, её могут перехватить в общественной "
            "Wi-Fi-сети.",
            f"Добавьте cookies атрибут Secure. {_ANY_DEVELOPER_RU}",
        ),
        "en": (
            "Cookies may be sent without encryption",
            "If the cookie keeps users logged in, it could be intercepted on public Wi-Fi.",
            f"Add the Secure attribute to cookies. {_ANY_DEVELOPER_EN}",
        ),
    },
    "cookies.httponly": {
        "ru": (
            "Cookies доступны скриптам на странице",
            "Если на сайт внедрят вредоносный скрипт, он сможет прочитать эти cookies, в том "
            "числе данные входа.",
            f"Добавьте cookies входа атрибут HttpOnly. {_ANY_DEVELOPER_RU}",
        ),
        "en": (
            "Cookies are readable by page scripts",
            "If a malicious script is injected, it can read these cookies, including login "
            "sessions.",
            f"Add the HttpOnly attribute to session cookies. {_ANY_DEVELOPER_EN}",
        ),
    },
    "cookies.samesite": {
        "ru": (
            "Для cookies не задана защита от запросов с чужих сайтов",
            "Атрибут SameSite снижает риск, что чужой сайт выполнит действие от имени вашего "
            "посетителя.",
            f"Добавьте cookies атрибут SameSite=Lax или Strict. {_ANY_DEVELOPER_RU}",
        ),
        "en": (
            "Cookies lack cross-site request protection",
            "The SameSite attribute reduces the risk of another site performing actions on "
            "behalf of your visitor.",
            f"Add SameSite=Lax or Strict to cookies. {_ANY_DEVELOPER_EN}",
        ),
    },
    "cookies.samesite_none_insecure": {
        "ru": (
            "Cookies настроены для чужих сайтов без шифрования",
            "SameSite=None без Secure современные браузеры отклоняют, а там, где принимают, "
            "cookie передаётся небезопасно.",
            f"Добавьте Secure или откажитесь от SameSite=None. {_ANY_DEVELOPER_RU}",
        ),
        "en": (
            "Cross-site cookies without encryption",
            "Modern browsers reject SameSite=None without Secure, and where accepted the cookie "
            "is sent insecurely.",
            f"Add Secure or stop using SameSite=None. {_ANY_DEVELOPER_EN}",
        ),
    },
    "info.stack_headers": {
        "ru": (
            "Сайт сообщает, на каком ПО он работает",
            "Сама по себе это не уязвимость, но она упрощает злоумышленникам подбор атак "
            "под вашу версию ПО.",
            "По возможности скройте версии в заголовках Server и X-Powered-By.",
        ),
        "en": (
            "The site reveals its software",
            "Not a vulnerability by itself, but it helps attackers pick attacks for your "
            "software version.",
            "Where possible, hide versions in the Server and X-Powered-By headers.",
        ),
    },
    "redirect.external": {
        "ru": (
            "Страница перенаправляет на другой сайт",
            "Это может быть нормально (например, вход через внешний сервис), но стоит убедиться, "
            "что перенаправление задумано.",
            "Проверьте, что адрес перенаправления ожидаемый.",
        ),
        "en": (
            "A page redirects to another site",
            "This may be intended (for example, external sign-in), but confirm it is expected.",
            "Check that the redirect destination is expected.",
        ),
    },
}

RULE_TEXTS["wordpress.components"] = {
    "ru": (
        "Плагины и темы WordPress, найденные на сайте",
        "Устаревшие плагины и темы — самая частая причина взлома сайтов на WordPress. "
        "Список составлен по коду страниц, поэтому может быть неполным, а версии — неточными.",
        "Проверьте, что всё из списка обновлено до последних версий, а неиспользуемые плагины "
        "и темы удалены. Включите автообновления там, где это безопасно.",
    ),
    "en": (
        "WordPress plugins and themes found on the site",
        "Outdated plugins and themes are the most common way WordPress sites get hacked. "
        "The list comes from page code, so it may be incomplete and versions may be inexact.",
        "Make sure everything listed is updated to the latest version and remove unused "
        "plugins and themes. Enable automatic updates where it is safe.",
    ),
}

_PREFIX_TEXTS: dict[str, dict[str, RuleText]] = {
    "secret.": {
        "ru": (
            "В коде сайта найдено похожее на ключ доступа",
            "Если это настоящий секретный ключ, его может использовать любой посетитель — "
            "например, чтобы тратить ваши платные лимиты или получить доступ к данным.",
            "Разработчику: проверить находку; если ключ настоящий — отозвать его, выпустить "
            "новый и убрать из кода, доступного в браузере.",
        ),
        "en": (
            "Something that looks like an access key was found in site code",
            "If it is a real secret key, any visitor could use it, for example to spend your "
            "paid quotas or access data.",
            "For your developer: verify the finding; if the key is real, revoke it, issue a new "
            "one and remove it from browser-visible code.",
        ),
    },
    "wordpress.": RULE_TEXTS["wordpress.components"],
    "cms.detected.": {
        "ru": (
            "Определена платформа сайта",
            "Это справочная информация. Устаревшие версии CMS и плагинов — самая частая причина "
            "взломов небольших сайтов.",
            "Держите CMS, темы и плагины обновлёнными и удалите неиспользуемые.",
        ),
        "en": (
            "Site platform detected",
            "For information. Outdated CMS and plugin versions are the most common cause of "
            "small-site compromises.",
            "Keep the CMS, themes and plugins updated and remove unused ones.",
        ),
    },
}


def rule_text(rule_id: str, lang: str) -> RuleText | None:
    """Return the plain-language text for a rule, or None when none exists."""
    texts = RULE_TEXTS.get(rule_id)
    if texts is None:
        texts = next(
            (value for prefix, value in _PREFIX_TEXTS.items() if rule_id.startswith(prefix)),
            None,
        )
    return None if texts is None else texts[lang]


UI: dict[str, dict[str, str]] = {
    "ru": {
        "title": "Отчёт о безопасности сайта",
        "prepared_by": "Подготовлено",
        "checked_on": "Дата проверки",
        "status_red": "Требуются срочные действия",
        "status_yellow": "Есть важные замечания",
        "status_green": "Серьёзных проблем не найдено",
        "status_unknown": "Сайт не удалось полностью проверить",
        "status_red_text": "Найдены проблемы, которые уже сейчас могут вредить бизнесу. "
        "Начните с раздела «Срочно».",
        "status_yellow_text": "Критичных проблем нет, но есть настройки, которые стоит "
        "исправить в ближайшее время.",
        "status_green_text": "Автоматическая проверка не выявила серьёзных проблем. "
        "Ниже — рекомендации для дополнительной защиты.",
        "status_unknown_text": "Главная страница не ответила корректно, поэтому часть проверок "
        "не выполнена. Результаты ниже неполные.",
        "areas": "Что проверено",
        "area_ok": "В порядке",
        "area_urgent": "Срочно",
        "area_issues": "Есть замечания",
        "area_detected": "Определена",
        "area_not_detected": "Не определена",
        "area_failed": "Не удалось проверить",
        "area_not_checked": "Не проверялось",
        "area_tls": "SSL-сертификат",
        "area_tls_desc": "Действует ли сертификат и когда истекает",
        "area_email": "Защита почты",
        "area_email_desc": "SPF и DMARC — защита от писем, подделанных под ваш домен",
        "area_site": "Настройки безопасности сайта",
        "area_site_desc": "Защитные заголовки, cookies, перенаправления",
        "area_cms": "Платформа сайта",
        "area_cms_desc": "Какая CMS используется (WordPress, Joomla и др.). "
        "Версии на известные уязвимости здесь не проверяются.",
        "area_js": "Утечки ключей",
        "area_js_desc": "Ключи доступа в коде, который видят посетители",
        "changes": "Изменения с прошлой проверки",
        "changes_fixed": "Исправлено (подтверждено повторной проверкой)",
        "changes_new": "Новые проблемы",
        "changes_regressed": "Проблемы вернулись после исправления",
        "changes_changed": "Изменилась важность",
        "changes_present": "Остаются без изменений",
        "changes_unverified": "Больше не обнаружены, но исправление не подтверждено",
        "actions": "Что нужно сделать",
        "level_high": "Срочно",
        "level_medium": "Важно",
        "level_low": "Рекомендуется",
        "level_info": "К сведению",
        "why": "Что это значит",
        "todo": "Что сделать",
        "validate": "Автоматическая проверка не уверена в этой находке — "
        "пусть специалист подтвердит её перед исправлением.",
        "pages": "Затронуто адресов",
        "details": "Технические детали для разработчика",
        "no_actions": "Действий не требуется.",
        "components_count": "плагинов и тем: {count}",
        "ownership_verified": "Владение сайтом подтверждено",
        "ownership_dns": "DNS-запись",
        "ownership_file": "файл на сайте",
        "area_cms_desc_checked": "Какая CMS используется, а также плагины и темы WordPress. "
        "Версии с известными номерами сверены с базой уязвимостей Wordfence от {date}.",
        "vuln_title": "{kind} «{name}» версии {version} содержит известные уязвимости",
        "vuln_why": "Уязвимости в плагинах и темах — самая частая причина взлома сайтов на "
        "WordPress. Для известных уязвимостей часто существуют готовые инструменты атаки.",
        "vuln_todo_fixed": "Обновите до версии {version} или новее. Перед обновлением сделайте "
        "резервную копию сайта.",
        "vuln_todo_nofix": "Исправленной версии пока нет. Замените компонент на аналог или "
        "удалите его, если он не нужен.",
        "vuln_change": "{kind} WordPress с уязвимостями: {name}",
        "vuln_source": "Данные об уязвимостях WordPress: Wordfence Intelligence (база от {date}).",
        "kind_plugin": "Плагин",
        "kind_theme": "Тема",
        "col_kind": "Тип",
        "col_name": "Название",
        "col_version": "Версия",
        "version_unknown": "не определена",
        "disclaimer": "Отчёт составлен автоматической проверкой без вмешательства в работу "
        "сайта. Он не гарантирует отсутствие уязвимостей и не заменяет полноценный аудит "
        "безопасности. Проверка выполнялась с разрешения владельца сайта.",
    },
    "en": {
        "title": "Website security report",
        "prepared_by": "Prepared by",
        "checked_on": "Checked on",
        "status_red": "Urgent action needed",
        "status_yellow": "Important issues found",
        "status_green": "No serious issues found",
        "status_unknown": "The site could not be fully checked",
        "status_red_text": "Some problems may already be hurting your business. "
        "Start with the 'Urgent' items.",
        "status_yellow_text": "Nothing critical, but some settings should be fixed soon.",
        "status_green_text": "The automated check found no serious problems. "
        "Below are recommendations for extra protection.",
        "status_unknown_text": "The home page did not respond correctly, so some checks did not "
        "run. The results below are incomplete.",
        "areas": "What was checked",
        "area_ok": "OK",
        "area_urgent": "Urgent",
        "area_issues": "Issues found",
        "area_detected": "Detected",
        "area_not_detected": "Not detected",
        "area_failed": "Could not check",
        "area_not_checked": "Not checked",
        "area_tls": "SSL certificate",
        "area_tls_desc": "Whether the certificate is valid and when it expires",
        "area_email": "Email protection",
        "area_email_desc": "SPF and DMARC — protection against email spoofing your domain",
        "area_site": "Site security settings",
        "area_site_desc": "Security headers, cookies, redirects",
        "area_cms": "Site platform",
        "area_cms_desc": "Which CMS the site runs (WordPress, Joomla, etc.). "
        "Versions are not checked for known vulnerabilities here.",
        "area_js": "Leaked keys",
        "area_js_desc": "Access keys in code that visitors can see",
        "changes": "Changes since the last check",
        "changes_fixed": "Fixed (confirmed by recheck)",
        "changes_new": "New issues",
        "changes_regressed": "Issues that came back",
        "changes_changed": "Importance changed",
        "changes_present": "Still open",
        "changes_unverified": "No longer detected, but the fix is not confirmed",
        "actions": "What to do",
        "level_high": "Urgent",
        "level_medium": "Important",
        "level_low": "Recommended",
        "level_info": "For information",
        "why": "What it means",
        "todo": "What to do",
        "validate": "The automated check is not certain about this finding — "
        "have a specialist confirm it before fixing.",
        "pages": "Affected addresses",
        "details": "Technical details for your developer",
        "no_actions": "No action needed.",
        "components_count": "plugins and themes: {count}",
        "ownership_verified": "Site ownership verified",
        "ownership_dns": "DNS record",
        "ownership_file": "file on the site",
        "area_cms_desc_checked": "Which CMS the site runs, plus WordPress plugins and themes. "
        "Known versions were checked against the Wordfence vulnerability database of {date}.",
        "vuln_title": "{kind} '{name}' version {version} has known vulnerabilities",
        "vuln_why": "Plugin and theme vulnerabilities are the most common way WordPress sites "
        "get hacked. Ready-made attack tools often exist for known vulnerabilities.",
        "vuln_todo_fixed": "Update to version {version} or later. Back up the site first.",
        "vuln_todo_nofix": "No fixed version is available yet. Replace the component or remove "
        "it if it is not needed.",
        "vuln_change": "WordPress {kind} with known vulnerabilities: {name}",
        "vuln_source": "WordPress vulnerability data: Wordfence Intelligence (database of {date}).",
        "kind_plugin": "Plugin",
        "kind_theme": "Theme",
        "col_kind": "Type",
        "col_name": "Name",
        "col_version": "Version",
        "version_unknown": "unknown",
        "disclaimer": "This report was produced by an automated, non-intrusive check. It does "
        "not guarantee the absence of vulnerabilities and does not replace a full security "
        "audit. The check was performed with the site owner's permission.",
    },
}
