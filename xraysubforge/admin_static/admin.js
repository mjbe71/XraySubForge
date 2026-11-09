"use strict";
(() => {
  const BASE = document.documentElement.dataset.base;
  const FIELDS = ["remark", "protocol", "tag", "address", "port", "network", "security", "sni", "host", "path", "flag"];
  const OPS = ["equals", "not_equals", "contains", "icontains", "not_contains", "startswith", "endswith", "regex", "iregex",
    "in", "not_in", "exists", "gt", "gte", "lt", "lte"];
  const COMBINATORS = ["all", "any", "not"];

  const STR = {
    en: {
      title: "XraySubForge admin", password: "Password", login: "Log in", logout: "Log out", save: "Save", saved: "Saved. Changes apply on the next request.",
      unsaved: "Unsaved changes", disabled: "The admin panel is disabled. Set admin.password_hash in config.json.",
      rules: "Rules", groups: "Groups", patches: "Patches", settings: "Server & panel", raw: "JSON",
      add: "+ Add", remove: "Delete", up: "Up", down: "Down", enabled: "Enabled", id: "Name (id)",
      when: "When (conditions)", whenHint: "All conditions must hold. Leave empty to match every config. With several words in one row, any one of them is enough.",
      addCond: "+ Condition", jsonMode: "Edit as JSON", rowsMode: "Edit as rows", notSimple: "This condition is too complex for rows; use JSON.",
      field: "field", op: "operator", value: "value",
      do: "Action", keep: "keep (leave alone)", drop: "drop (remove)", pin_top: "pin to top", pin_bottom: "pin to bottom",
      rulesHint: "Evaluated in order; the first matching rule decides. Configs matching no rule are kept.",
      groupsHint: "Each group merges matching configs into one balancer config (per bucket when split by a value).",
      patchesHint: "Merge your own JSON into matching configs. A null value deletes a key.",
      splitField: "Split by field", splitRegex: "Split regex (first capture group = bucket)", name: "Output name ({split} {n} {group})",
      type: "Balancer type", params: "Strategy settings (JSON)", probe: "Probe / observatory (JSON)", probeKind: "Probe kind",
      auto: "automatic", memberCost: "Member costs (JSON list)", minMembers: "Minimum members", removeMembers: "Remove the single configs from the output",
      position: "Position", default: "where the first member was", top: "top", bottom: "bottom",
      stage: "Stage", source: "source (before rules/groups)", output: "output (after groups)", target: "Target", config: "whole config", outbound: "each proxy outbound",
      merge: "Merge (JSON)", routingPre: "Routing rules to add first (JSON list)", routingPost: "Routing rules to add last (JSON list)",
      server: "Server", panel: "Panel", restartNote: "Changing the address, port, route, HTTPS or workers needs a restart of the service.", adminNote: "Login settings (admin.*) are edited in config.json only.",
      host: "Listen address", port: "Port", route: "Public path", subidRegex: "Allowed id (regex)", workers: "Workers", threads: "Threads",
      panelUrl: "Panel JSON-subscription URL", pageUrl: "Browser redirect URL (optional)", timeout: "Timeout (s)", verifyTls: "Verify TLS certificate",
      headers: "Extra request headers (JSON)", passHeaders: "Response headers passed to clients (JSON list)",
      apply: "Apply", jsonBad: "Invalid JSON", preview: "Preview", subid: "Subscription id", fetch: "Fetch from panel", pasteJson: "…or paste a panel response",
      useJson: "Use pasted JSON", sampleN: "Sample: {n} config(s)", noSample: "Load a sample to see what your rules do.",
      cfgTable: "What happens to each config", outputs: "Result", errors: "Problems", warnings: "Notes", inOut: "in output",
      members: "members", showJson: "click to show JSON", wrongPw: "Wrong password", fetching: "Fetching…", hint_split: "Empty regex = one balancer for all",
      newItem: "new", confirmDel: "Delete this item?",
      tlsCert: "HTTPS certificate file (optional)", tlsKey: "HTTPS key file (optional)",
      chains: "Chains", chainsHint: "Build a config whose own outbound (yours, e.g. WARP) is dialed through an exit config from the panel. Use {account.x}, {exit.address}, {split}, {n} inside the entry.",
      exitWhen: "Exit configs (conditions)", entry: "Entry outbound (JSON)", entryHint: "Placeholders: {account.key} from the accounts source, {exit.address} (any field), {choice.name} (see below), {split}, {n}.",
      choices: "Choices per user (JSON, optional)", choicesHint: "For example {\"endpoint\": [\"1.2.3.4\", \"5.6.7.8\"]}: each user gets one value, always the same one, available as {choice.endpoint}.",
      throughExit: "Dial the entry through the exit config", removeExit: "Remove the exit config from the output", hint_chain_split: "Empty regex = one chain from the first match",
      accounts: "Accounts (values for {account.*})", accountFile: "Accounts file", accountHint: "JSON file next to config.json; keep it private.", accountDefault: "Shared account (JSON, optional; the file wins)",
      regTitle: "Automatic WARP accounts", regEnabled: "Create a WARP account for each new user automatically (needs the accounts file; uses Cloudflare's unofficial API)", regRetry: "Wait after a failure (s)", regApi: "API address (optional)", regVersion: "Client version (optional)",
      regNow: "Create account now", regSubid: "Subscription id (empty = the shared account)", regSaveFirst: "Save the settings first (the accounts file must be saved).", regOk: "Account created.", regExists: "That user already has an account.",
    },
    fa: {
      title: "مدیریت XraySubForge", password: "رمز عبور", login: "ورود", logout: "خروج", save: "ذخیره", saved: "ذخیره شد. تغییرات از درخواست بعدی اعمال می‌شود.",
      unsaved: "تغییرات ذخیره‌نشده", disabled: "پنل ادمین غیرفعال است. در config.json مقدار admin.password_hash را بگذارید.",
      rules: "قوانین", groups: "گروه‌ها", patches: "پچ‌ها", settings: "سرور و پنل", raw: "JSON",
      add: "+ افزودن", remove: "حذف", up: "بالا", down: "پایین", enabled: "فعال", id: "نام (id)",
      when: "شرط‌ها", whenHint: "همهٔ شرط‌ها باید برقرار باشند. خالی = همهٔ کانفیگ‌ها. اگر در یک ردیف چند کلمه بگذارید، یکی از آن‌ها کافی است.",
      addCond: "+ شرط", jsonMode: "ویرایش با JSON", rowsMode: "ویرایش با ردیف", notSimple: "این شرط برای ردیف‌ها پیچیده است؛ از JSON استفاده کنید.",
      field: "فیلد", op: "عملگر", value: "مقدار",
      do: "کار", keep: "keep (دست نزن)", drop: "drop (حذف)", pin_top: "بالای لیست", pin_bottom: "پایین لیست",
      rulesHint: "به ترتیب بررسی می‌شوند و اولین قانونِ مطابق تصمیم می‌گیرد. کانفیگی که هیچ قانونی نخورد نگه داشته می‌شود.",
      groupsHint: "هر گروه کانفیگ‌های مطابق را در یک کانفیگ بالانسر ادغام می‌کند (اگر بر اساس مقدار تقسیم شود، برای هر دسته یکی).",
      patchesHint: "JSON خودتان را در کانفیگ‌های مطابق ادغام کنید. مقدار null کلید را حذف می‌کند.",
      splitField: "تقسیم بر اساس فیلد", splitRegex: "regex تقسیم (گروه اول = دسته)", name: "اسم خروجی ({split} {n} {group})",
      type: "نوع بالانسر", params: "تنظیمات strategy (JSON)", probe: "probe / observatory (JSON)", probeKind: "نوع probe",
      auto: "خودکار", memberCost: "هزینهٔ اعضا (لیست JSON)", minMembers: "حداقل تعداد عضو", removeMembers: "کانفیگ‌های تکی از خروجی حذف شوند",
      position: "جایگاه", default: "جای اولین عضو", top: "بالا", bottom: "پایین",
      stage: "مرحله", source: "source (قبل از قوانین و گروه‌ها)", output: "output (بعد از گروه‌ها)", target: "هدف", config: "کل کانفیگ", outbound: "هر outbound پروکسی",
      merge: "ادغام (JSON)", routingPre: "قوانین مسیریابی برای اول لیست (لیست JSON)", routingPost: "قوانین مسیریابی برای آخر لیست (لیست JSON)",
      server: "سرور", panel: "پنل", restartNote: "تغییر آدرس، پورت، مسیر، HTTPS یا تعداد worker به راه‌اندازی مجدد سرویس نیاز دارد.", adminNote: "تنظیمات ورود (admin.*) فقط در config.json ویرایش می‌شوند.",
      host: "آدرس شنود", port: "پورت", route: "مسیر عمومی", subidRegex: "شناسهٔ مجاز (regex)", workers: "Worker", threads: "Thread",
      panelUrl: "آدرس ساب JSON پنل", pageUrl: "آدرس ریدایرکت مرورگر (اختیاری)", timeout: "Timeout (ثانیه)", verifyTls: "بررسی گواهی TLS",
      headers: "هدرهای اضافهٔ درخواست (JSON)", passHeaders: "هدرهای پاسخ که به کلاینت می‌روند (لیست JSON)",
      apply: "اعمال", jsonBad: "JSON نامعتبر", preview: "پیش‌نمایش", subid: "شناسهٔ ساب", fetch: "گرفتن از پنل", pasteJson: "…یا پاسخ پنل را اینجا بچسبانید",
      useJson: "استفاده از JSON چسبانده‌شده", sampleN: "نمونه: {n} کانفیگ", noSample: "برای دیدن اثر قوانین، یک نمونه بگیرید.",
      cfgTable: "سرنوشت هر کانفیگ", outputs: "نتیجه", errors: "مشکلات", warnings: "توجه", inOut: "در خروجی",
      members: "عضو", showJson: "برای دیدن JSON کلیک کنید", wrongPw: "رمز اشتباه است", fetching: "در حال گرفتن…", hint_split: "regex خالی = یک بالانسر برای همه",
      newItem: "جدید", confirmDel: "این مورد حذف شود؟",
      tlsCert: "فایل گواهی HTTPS (اختیاری)", tlsKey: "فایل کلید HTTPS (اختیاری)",
      chains: "زنجیره‌ها", chainsHint: "کانفیگی بسازید که outbound خودتان (مثلاً WARP) از داخل یک کانفیگ خروجی پنل عبور می‌کند. داخل entry می‌توانید از {account.x}، {exit.address}، {split} و {n} استفاده کنید.",
      exitWhen: "کانفیگ‌های خروجی (شرط‌ها)", entry: "outbound ورودی (JSON)", entryHint: "جاگذارها: {account.key} از منبع حساب‌ها، {exit.address} (هر فیلد)، {choice.name} (پایین را ببینید)، {split} و {n}.",
      choices: "انتخاب برای هر کاربر (JSON، اختیاری)", choicesHint: "مثلاً {\"endpoint\": [\"1.2.3.4\", \"5.6.7.8\"]}: هر کاربر یکی از مقادیر را می‌گیرد (همیشه همان یکی) و با {choice.endpoint} در دسترس است.",
      throughExit: "ورودی از داخل کانفیگ خروجی عبور کند", removeExit: "کانفیگ خروجی از نتیجه حذف شود", hint_chain_split: "regex خالی = یک زنجیره از اولین مطابق",
      accounts: "حساب‌ها (مقدار {account.*})", accountFile: "فایل حساب‌ها", accountHint: "فایل JSON کنار config.json؛ محرمانه نگه دارید.", accountDefault: "حساب مشترک (JSON، اختیاری؛ فایل اولویت دارد)",
      regTitle: "حساب WARP خودکار", regEnabled: "برای هر کاربر جدید خودکار حساب WARP بساز (به فایل حساب‌ها نیاز دارد؛ از API غیررسمی Cloudflare استفاده می‌کند)", regRetry: "صبر پس از شکست (ثانیه)", regApi: "آدرس API (اختیاری)", regVersion: "نسخهٔ کلاینت (اختیاری)",
      regNow: "همین الان حساب بساز", regSubid: "شناسهٔ ساب (خالی = حساب مشترک)", regSaveFirst: "ابتدا تنظیمات را ذخیره کنید (فایل حساب‌ها باید ذخیره شده باشد).", regOk: "حساب ساخته شد.", regExists: "این کاربر از قبل حساب دارد.",
    },
  };

  Object.assign(STR.en, {
    start: "Start", rules: "Filter & order", groups: "Balancers", chains: "Via another route (WARP)", patches: "Advanced edits", settings: "Settings",
    rulesHint: "Decide which configs your users get. Rules run from top to bottom and the first one that matches decides. Example: if the name contains \"test\" → remove it.",
    groupsHint: "Merge several configs into one smart config that picks the best server by itself (load balancing). Example: every config named \"Germany-…\" becomes a single \"Germany\" config.",
    chainsHint: "Send traffic through a second hop such as WARP: your own outbound is dialed through one of the panel's configs. The Start page has an easy setup for WARP.",
    patchesHint: "For experts: merge your own JSON into the configs (DNS, routing, fragment, ...). A null value deletes a key.",
    do: "Then", keep: "Keep it (and skip the later rules)", drop: "Remove it", pin_top: "Move it to the top", pin_bottom: "Move it to the bottom",
    revert: "Discard changes", whenIf: "If", fieldCustom: "other (JSON path)", andWord: "and", everyConfig: "every config",
    wizTitle: "Setup guide", wizIntro: "Follow the steps. Each one checks that things work. You can leave and come back at any time; nothing changes until you save.",
    step1: "Connect to your panel", step2: "Try a subscription", step3: "Choose what to change", step4: "Review and save",
    s1help: "Enter the JSON-subscription address of your 3x-ui panel, without the user's id at the end. In 3x-ui: Panel settings → Subscription → JSON.",
    s1helpRaw: "Enter the normal (raw) subscription address of your 3x-ui panel, without the user's id at the end. In 3x-ui: Panel settings → Subscription. The JSON configs are built here, so the JSON subscription can stay off.",
    rawUrlNeeded: "Panel raw subscription URL",
    checkConn: "Check connection", next: "Next", back: "Back", skip: "Skip",
    s2help: "Enter the subscription id of any real user (the last part of their link). We fetch it from the panel and show what it contains.",
    found: "Found {n} config(s):", more: "… and {n} more",
    s3help: "Pick what you want. Nothing here is required: with nothing selected, users get the panel's subscription unchanged. Everything created here can be edited later in the other tabs.",
    goalHide: "Hide some configs", goalHideHelp: "Remove configs whose name contains any of these:",
    goalBalance: "Balance configs automatically", goalBalanceHelp: "Merge configs whose name contains any of these into one smart config:",
    balSplit: "One balancer per … (optional pattern; the first (group) is the name, e.g. ^[^-]+-([^-]+) )", balType: "Balancer type",
    balNote: "A health probe with common defaults is added; you can change it in the Balancers tab.",
    goalWarp: "Send traffic through WARP (over MASQUE)", goalWarpHelp: "Use configs whose name contains any of these as the exit:",
    warpEndpoint: "WARP endpoint addresses (one per line)", warpEndpointHint: "Each user gets one of these (always the same one for the same user).", warpAuto: "Create a WARP account for each user automatically",
    warpNote: "The outbound is a working WARP-over-MASQUE example; you can edit every field in the \"Via another route\" tab. Automatic accounts use Cloudflare's unofficial API.",
    matches: "matches {n} of {m} in your sample", noMatchSample: "Try a subscription in step 2 to see how many match.",
    s4help: "This is what your users will get. Look at the list on the right, run the checks, then save.",
    checksTitle: "Checks", runChecks: "Run the checks again", running: "Checking…",
    beforeAfter: "{a} config(s) from the panel → {b} for the user",
    saveFinish: "Save and finish", doneTitle: "Saved. You're done!", doneLink: "Link for your users (add the user's subscription id at the end):",
    copy: "Copy", copied: "Copied", goTabs: "You can fine-tune everything in the other tabs.",
    exp_drop_rule: "Removed by rule \"{rule}\"", exp_drop: "Removed", exp_top: "Moved to the top (\"{rule}\")", exp_bottom: "Moved to the bottom (\"{rule}\")",
    exp_keep_rule: "Kept by rule \"{rule}\"", exp_kept: "Kept as it is", exp_group: "Merged into balancer \"{g}\"", exp_chain: "Exit of \"{c}\"",
    colWhat: "What happens",
    restartBtn: "Restart the service", restartConfirm: "Restart the service now? The panel is unavailable for a few seconds.", restarting: "Restarting… waiting for the service to come back.",
    restarted: "The service is back.", restartFail: "Could not restart: {err}", restartManual: "To restart: run \"sudo sforge restart\" on the server.", restartNeeded: "You changed server settings: restart the service to apply them.", chipsHint: "Type a word, then press Enter or +. Add as many as you like.", addWord: "+ Add", noAccountYet: "The WARP chain \"{id}\" cannot be shown here yet: it needs a WARP account. With automatic accounts on, each user's account is created the first time they fetch their subscription.",
    c_panel_url_ok: "Panel address is set", c_panel_url_fail: "The panel address is not set",
    c_panel_reach_ok: "The panel is reachable", c_panel_reach_warn: "The panel answered with an error (HTTP {code})",
    c_panel_reach_fail_connect: "Cannot connect to the panel: wrong address or port, or a firewall is blocking it",
    c_panel_reach_fail_tls: "The panel's TLS certificate is not trusted: fix it or turn off \"Verify TLS certificate\" in Settings",
    c_panel_reach_fail_timeout: "The panel did not answer in time",
    c_sample_ok: "The panel gave {n} config(s) for your test id", c_sample_fail: "The panel refused the test id: {reason}", c_sample_skip: "Test id not tried (go back to step 2 to try one)",
    c_https_ok: "HTTPS is on (certificate valid for {days} more days)", c_https_ok_proxy: "You are connected over HTTPS",
    c_https_warn: "The HTTPS certificate expires in {days} day(s)", c_https_warn_off: "Users would reach the subscription over plain HTTP: run \"sudo sforge tls\" on the server",
    c_https_fail_unreadable: "HTTPS is on but the certificate file cannot be read",
    c_admin_pw_ok: "The admin password is stored safely", c_admin_pw_warn: "The admin password is stored as plain text: run \"sudo sforge set-admin-password\"",
    c_config_ok: "The settings are valid", c_config_warn: "{n} note(s) about the settings", c_config_fail: "{n} problem(s) in the settings",
    c_accounts_ok: "WARP accounts are ready", c_accounts_fail_none: "The WARP chain has no account values: turn on automatic accounts",
    c_accounts_fail_unwritable: "Automatic accounts need a folder the service can write to for the accounts file",
  });
  Object.assign(STR.fa, {
    modeTitle: "چه کاری انجام شود؟", modeEngine: "ساب‌ها با قوانین من بازسازی شوند (پیشرفته)", modeProxy: "فقط ساب‌های پنل من را عبور بده (ریورس‌پروکسی ساده)",
    modeProxyHelp: "کاربران ساب پنل را بدون تغییر از دامنهٔ شما می‌گیرند. خود پنل می‌تواند روی localhost بماند. قوانین، بالانسر و زنجیره اعمال نمی‌شوند.",
    proxyHelp: "آدرس هر ساب را که می‌خواهید عبور کند همان‌طور که در 3x-ui هست (تنظیمات پنل ← اشتراک) وارد کنید، بدون شناسهٔ کاربر در انتها. فرمتی که خالی بماند خاموش است.",
    jsonUrl: "آدرس ساب JSON (اختیاری)", doneLinkJson: "لینک ساب JSON:",
    doneLinkRaw: "لینک ساب Raw:", doneLinkClash: "لینک ساب Clash:",
    proxyOnBanner: "حالت پروکسی روشن است: قوانین، بالانسر، زنجیره و پچ اعمال نمی‌شوند. از «شروع» یا «تنظیمات» عوضش کنید.",
  });
  Object.assign(STR.fa, {
    start: "شروع", rules: "فیلتر و ترتیب", groups: "بالانسر", chains: "عبور از مسیر دیگر (مثل WARP)", patches: "ویرایش پیشرفته", settings: "تنظیمات",
    rulesHint: "مشخص می‌کند کاربران کدام کانفیگ‌ها را بگیرند. قانون‌ها از بالا به پایین بررسی می‌شوند و اولین قانونِ مطابق تصمیم می‌گیرد. مثال: اگر نام شامل «test» بود ← حذف شود.",
    groupsHint: "چند کانفیگ را در یک کانفیگ هوشمند ادغام می‌کند که خودش بهترین سرور را انتخاب می‌کند (بالانس بار). مثال: همهٔ کانفیگ‌هایی که نامشان «Germany-…» است تبدیل به یک کانفیگ «Germany» می‌شوند.",
    chainsHint: "ترافیک را از یک پرش دوم مثل WARP عبور می‌دهد: outbound خودتان از داخل یکی از کانفیگ‌های پنل ساخته می‌شود. در صفحهٔ «شروع» برای WARP یک راه‌اندازی آسان هست.",
    patchesHint: "برای کاربران حرفه‌ای: JSON خودتان را در کانفیگ‌ها ادغام کنید (DNS، مسیریابی، fragment و ...). مقدار null کلید را حذف می‌کند.",
    do: "آنگاه", keep: "نگهش دار (و قوانین بعدی را نادیده بگیر)", drop: "حذفش کن", pin_top: "ببرش بالای لیست", pin_bottom: "ببرش پایین لیست",
    revert: "لغو تغییرات", whenIf: "اگر", fieldCustom: "دیگر (مسیر JSON)", andWord: "و", everyConfig: "همهٔ کانفیگ‌ها",
    wizTitle: "راهنمای راه‌اندازی", wizIntro: "مرحله‌به‌مرحله جلو بروید. هر مرحله بررسی می‌کند که همه‌چیز درست کار کند. هر وقت خواستید می‌توانید خارج شوید و برگردید؛ تا ذخیره نکنید چیزی عوض نمی‌شود.",
    step1: "اتصال به پنل", step2: "امتحان یک اشتراک", step3: "انتخاب تغییرات", step4: "بررسی و ذخیره",
    s1help: "آدرس ساب JSON پنل 3x-ui را وارد کنید، بدون شناسهٔ کاربر در انتها. در 3x-ui: تنظیمات پنل ← اشتراک ← JSON.",
    s1helpRaw: "آدرس ساب معمولی (خام) پنل 3x-ui را وارد کنید، بدون شناسهٔ کاربر در انتها. در 3x-ui: تنظیمات پنل ← اشتراک. کانفیگ‌های JSON همین‌جا ساخته می‌شوند، پس ساب JSON می‌تواند خاموش بماند.",
    rawUrlNeeded: "آدرس ساب خام پنل",
    checkConn: "بررسی اتصال", next: "بعدی", back: "قبلی", skip: "رد کردن",
    s2help: "شناسهٔ ساب یک کاربر واقعی را وارد کنید (بخش آخر لینک او). آن را از پنل می‌گیریم و محتوایش را نشان می‌دهیم.",
    found: "{n} کانفیگ پیدا شد:", more: "… و {n} مورد دیگر",
    s3help: "هر چه می‌خواهید انتخاب کنید. هیچ‌کدام اجباری نیست: اگر چیزی انتخاب نکنید، کاربران همان ساب پنل را بدون تغییر می‌گیرند. هر چه اینجا ساخته شود بعداً در تب‌های دیگر قابل ویرایش است.",
    goalHide: "پنهان کردن بعضی کانفیگ‌ها", goalHideHelp: "کانفیگ‌هایی که نامشان شامل هر یک از این‌ها باشد حذف شوند:",
    goalBalance: "بالانس خودکار کانفیگ‌ها", goalBalanceHelp: "کانفیگ‌هایی که نامشان شامل هر یک از این‌ها باشد در یک کانفیگ هوشمند ادغام شوند:",
    balSplit: "برای هر … یک بالانسر (الگوی اختیاری؛ (گروه) اول = نام، مثلاً ^[^-]+-([^-]+) )", balType: "نوع بالانسر",
    balNote: "یک probe سلامت با مقادیر رایج اضافه می‌شود؛ در تب «بالانسر» می‌توانید تغییرش دهید.",
    goalWarp: "عبور ترافیک از WARP (روی MASQUE)", goalWarpHelp: "کانفیگ‌هایی که نامشان شامل هر یک از این‌ها باشد به‌عنوان خروجی استفاده شوند:",
    warpEndpoint: "آدرس‌های endpoint وارپ (هر خط یکی)", warpEndpointHint: "هر کاربر یکی از این‌ها را می‌گیرد (برای یک کاربر همیشه همان یکی).", warpAuto: "برای هر کاربر خودکار حساب WARP بساز",
    warpNote: "این outbound یک نمونهٔ کارکنِ WARP روی MASQUE است؛ همهٔ فیلدهایش را در تب «عبور از مسیر دیگر» می‌توانید ویرایش کنید. حساب خودکار از API غیررسمی Cloudflare استفاده می‌کند.",
    matches: "{n} مورد از {m} کانفیگ نمونهٔ شما مطابقت دارد", noMatchSample: "در مرحلهٔ ۲ یک اشتراک را امتحان کنید تا تعداد مطابقت‌ها را ببینید.",
    s4help: "این همان چیزی است که کاربران می‌گیرند. فهرست سمت دیگر را ببینید، بررسی‌ها را اجرا کنید و ذخیره کنید.",
    checksTitle: "بررسی‌ها", runChecks: "اجرای دوبارهٔ بررسی‌ها", running: "در حال بررسی…",
    beforeAfter: "{a} کانفیگ از پنل ← {b} کانفیگ برای کاربر",
    saveFinish: "ذخیره و پایان", doneTitle: "ذخیره شد. کار تمام است!", doneLink: "لینک برای کاربران (شناسهٔ ساب هر کاربر را به انتها اضافه کنید):",
    copy: "کپی", copied: "کپی شد", goTabs: "همه‌چیز را در تب‌های دیگر می‌توانید دقیق‌تر تنظیم کنید.",
    exp_drop_rule: "با قانون «{rule}» حذف شد", exp_drop: "حذف شد", exp_top: "به بالای لیست رفت («{rule}»)", exp_bottom: "به پایین لیست رفت («{rule}»)",
    exp_keep_rule: "با قانون «{rule}» نگه داشته شد", exp_kept: "همان‌طور که هست می‌ماند", exp_group: "در بالانسر «{g}» ادغام شد", exp_chain: "خروجی «{c}»",
    colWhat: "چه می‌شود",
    restartBtn: "راه‌اندازی مجدد سرویس", restartConfirm: "سرویس همین حالا راه‌اندازی مجدد شود؟ پنل چند ثانیه در دسترس نیست.", restarting: "در حال راه‌اندازی مجدد… منتظر برگشتن سرویس هستیم.",
    restarted: "سرویس برگشت.", restartFail: "راه‌اندازی مجدد ممکن نشد: {err}", restartManual: "برای راه‌اندازی مجدد، روی سرور «sudo sforge restart» را بزنید.", restartNeeded: "تنظیمات سرور را تغییر داده‌اید: برای اعمال، سرویس را راه‌اندازی مجدد کنید.", chipsHint: "یک کلمه بنویسید و Enter یا «+ افزودن» را بزنید. هر تعداد می‌توانید اضافه کنید.", addWord: "+ افزودن", noAccountYet: "زنجیرهٔ WARP با نام «{id}» هنوز در اینجا قابل نمایش نیست: به حساب WARP نیاز دارد. اگر حساب خودکار روشن باشد، حساب هر کاربر هنگام اولین دریافت ساب او ساخته می‌شود.",
    c_panel_url_ok: "آدرس پنل تنظیم شده است", c_panel_url_fail: "آدرس پنل تنظیم نشده است",
    c_panel_reach_ok: "پنل در دسترس است", c_panel_reach_warn: "پنل با خطا پاسخ داد (HTTP {code})",
    c_panel_reach_fail_connect: "اتصال به پنل ممکن نیست: آدرس یا پورت اشتباه است یا فایروال جلویش را گرفته",
    c_panel_reach_fail_tls: "گواهی TLS پنل معتبر نیست: درستش کنید یا در تنظیمات «بررسی گواهی TLS» را خاموش کنید",
    c_panel_reach_fail_timeout: "پنل به‌موقع پاسخ نداد",
    c_sample_ok: "پنل برای شناسهٔ آزمایشی {n} کانفیگ داد", c_sample_fail: "پنل شناسهٔ آزمایشی را نپذیرفت: {reason}", c_sample_skip: "شناسهٔ آزمایشی امتحان نشد (برای امتحان به مرحلهٔ ۲ برگردید)",
    c_https_ok: "HTTPS روشن است (گواهی {days} روز دیگر معتبر است)", c_https_ok_proxy: "با HTTPS متصل هستید",
    c_https_warn: "گواهی HTTPS تا {days} روز دیگر منقضی می‌شود", c_https_warn_off: "کاربران ساب را با HTTP ساده می‌گیرند: روی سرور «sudo sforge tls» را بزنید",
    c_https_fail_unreadable: "HTTPS روشن است ولی فایل گواهی خوانده نمی‌شود",
    c_admin_pw_ok: "رمز ادمین امن ذخیره شده است", c_admin_pw_warn: "رمز ادمین به‌صورت متن ساده ذخیره شده: «sudo sforge set-admin-password» را بزنید",
    c_config_ok: "تنظیمات معتبر است", c_config_warn: "{n} نکته دربارهٔ تنظیمات", c_config_fail: "{n} مشکل در تنظیمات",
    c_accounts_ok: "حساب‌های WARP آماده‌اند", c_accounts_fail_none: "زنجیرهٔ WARP مقدار حساب ندارد: حساب خودکار را روشن کنید",
    c_accounts_fail_unwritable: "حساب خودکار به پوشه‌ای نیاز دارد که سرویس بتواند فایل حساب‌ها را در آن بنویسد",
  });

  Object.assign(STR.en, {
    output: "Output", order: "Order",
    orderHint: "Sort the final list. The first rule that matches a config gives it a rank; configs are then sorted by rank (lowest first), keeping the old order for equal ranks. A rule with no condition catches everything else.",
    rank: "Rank", rankHint: "Lower numbers come first.",
    outHint: "Settings applied to every returned config after balancers and chains were built. Everything is off until you turn it on.",
    outEnabled: "Apply the output settings", outWhen: "Only for configs matching",
    sectInbounds: "Inbounds & routing", sectDns: "DNS", sectTuning: "Balancer tuning", sectRemark: "Names",
    splitInbounds: "Separate socks and http inbounds (some apps do not work with the combined one)",
    dnsOut: "Add a dns-out outbound", blockUdp: "Block UDP port 443 (QUIC) so apps fall back to TCP",
    quicEdit: "Copy the built-in list here to edit it",
    sniffOver: "Sniffing: destOverride", sniffHint: "Protocols the socks and http inbounds sniff (default: http, tls, quic, fakedns).", routeOnly: "Sniffing routeOnly", socksPort: "socks port (empty = keep the panel's)", httpPort: "http port (empty = keep the panel's)",
    profile: "Profile", profileDefaultNote: "The default profile cannot be renamed or deleted. Pick another profile in the header to manage it.", profileManageNote: "Profile {n}: rename it, or delete it (its file is moved to profiles/trash/, not erased).", profileDefault: "default profile", profileNew: "+ New profile", profileName: "Name of the new profile (lowercase letters, digits, - or _)", profileCopy: "Start from a copy of the current profile (its accounts are not copied)? OK = copy, Cancel = empty", profileRestart: "Done. Restart the service so the routes match.", profileRename: "Rename", profileRemove: "Delete", profileDelete: "Delete profile {n}? Its file is moved to profiles/trash/, not erased.",
    quicDomains: "QUIC domains (empty = built-in list)", replaceRouting: "Replace the routing rules with the ones built here (keeps balancer rules)",
    domainStrategy: "Domain strategy", baseRules: "Base routing rules", baseOff: "off", baseBuiltin: "built-in (private and Iran go direct)", baseCustom: "custom list",
    baseRulesList: "Rules (JSON list)", baseRulesHint: "Rules added to every config; the built-in set sends private addresses and Iranian sites direct.",
    dedicatedDns: "Dedicated DNS for the proxies' own domains", ddIp: "DNS server IP", ddTag: "Tag",
    directDns: "Resolve domestic domains with the domestic DNS", ddRegex: "Domestic DNS tag pattern (regex)",
    samplingTitle: "Observatory sampling", samplingOff: "off (leave as is)", samplingFixed: "fixed number", samplingDiv: "from the number of members",
    samplingFixedN: "Samples", samplingDivN: "Members per sample", samplingExtra: "Extra samples",
    panelBal: "Tune the panel's own balancers", pbRtt: "Max RTT", pbFew: "\"Few\" means at most this many members", pbExpFew: "Expected (few members)", pbExpMany: "Expected (many members)",
    remarkTitle: "Rewrite names", remarkHint: "Each rule replaces the text matching the pattern. The \"only if\" pattern, when set, must match the name for the rule to run.",
    rwRegex: "Pattern", rwReplace: "Replace with", rwIf: "Only if name matches", addRule: "+ Add rule",
    usingDefaults: "Using the built-in defaults.", customize: "Customize",
    orWord: "or", notWord: "not",
    chainMode: "Direction", modeEntry: "entry first: your outbound is dialed through the panel config", modeExit: "exit first: the exit goes through your entry (e.g. client → WARP → exit)",
    chainEndpoints: "Endpoints", chainEndpointsHint: "Text with a placeholder, e.g. {account.masque.endpoints}; the address and port of the entry.",
    chainPick: "Pick", pickRandom: "random each time", pickUser: "same per user",
    chainExit: "Exit (JSON)", chainExitHint: "false = no exit config (solo). Or {\"from_account\": \"exits\", \"default_account\": \"exit\", \"user_id\": true}.",
    chainEntryMerge: "Entry merge (JSON)", chainEntryMergeHint: "Merged into the entry outbound; {account.x?} placeholders are left out when missing.",
    chainBefore: "Outbounds placed in front (JSON list)", chainBeforeHint: "Placeholders: {entry.address}, {entry.port}, {user.id}.",
    expandTitle: "Copies per server", expandOn: "Make several copies of every server (different addresses)",
    exCopies: "Copies", exServerBy: "Server key field", exServerRegex: "Server key regex", exAddresses: "Addresses to use", exAddrRegex: "Keep own address when it matches",
    exLayout: "Layout", exGrouped: "grouped", exBlocks: "blocks (rotated per block)", exPick: "Pick", exWhen: "Only for members matching",
    includeBalanced: "Also use configs that already are balancers",
    memberPosition: "Member position (JSON list)", memberPositionHint: "[{\"when\": {...}, \"at\": \"first\"|\"last\"}]",
    catchall: "Catch-all rules (JSON list)", catchallHint: "Routing rules sent to this balancer; the balancer tag is filled in.",
    memberPatch: "Member patches (JSON list)", memberPatchHint: "[{\"when\": {...}, \"merge\": {...}, \"random\": {...}}]",
    modeTitle: "What should it do?", modeEngine: "Reshape subscriptions with my rules (advanced)", modeProxy: "Only forward my panel's subscriptions (simple reverse proxy)",
    modeProxyHelp: "Users get the panel's subscriptions unchanged, from your domain. The panel itself can stay on localhost. Rules, balancers and chains are not applied.",
    rawUrl: "Raw subscription URL (optional)", clashUrl: "Clash subscription URL (optional)",
    formatUrlHint: "As in 3x-ui, without the user's id at the end. Leave empty to turn this format off.",
    rawRoute: "Public path for raw", clashRoute: "Public path for Clash",
    doneLinkRaw: "Raw subscription link:", doneLinkClash: "Clash subscription link:",
    proxyHelp: "Enter the address of each subscription you want to forward, as in 3x-ui (Panel settings → Subscription), without the user's id at the end. Leave a format empty to turn it off.",
    jsonUrl: "JSON subscription URL (optional)", doneLinkJson: "JSON subscription link:",
    proxyOnBanner: "Proxy mode is on: rules, balancers, chains and patches are not applied. Change this in Start or Settings.",
    mpTitle: "Member patches", mpHint: "Changes applied to every config that joins this balancer. Patches run in order.",
    mpPatch: "Patch", mpAll: "every member", mpAdd: "+ Patch", mpMerge: "Merge", mpMergeHint: "Always applied, e.g. fingerprint, alpn, sockopt.",
    mpRandom: "Random choice", mpRandomHint: "Each config gets one of the presets, picked at random.",
    mpFragment: "Fragment presets", mpCipher: "Cipher suites presets", mpOther: "Other random choices (JSON)",
    mpAddFragment: "+ Fragment presets", mpAddCipher: "+ Cipher suites presets", mpAddPreset: "Add preset…", mpCustom: "Custom", mpAddStep: "+ Step", mpRemoveStep: "Remove step",
    mpCipherHint: "One cipher suite per line (or separated by a colon).", mpEditJson: "Edit as JSON", mpEditForm: "Edit as form",
    mpNotForm: "These patches use keys the form does not show.",
  });
  Object.assign(STR.fa, {
    output: "خروجی", order: "ترتیب",
    orderHint: "چیدمان لیست نهایی. اولین قانونی که با یک کانفیگ بخواند به آن رتبه می‌دهد؛ بعد کانفیگ‌ها بر اساس رتبه (کمترین اول) مرتب می‌شوند و برای رتبهٔ برابر ترتیب قبلی می‌ماند. قانون بدون شرط بقیه را می‌گیرد.",
    rank: "رتبه", rankHint: "عدد کمتر زودتر می‌آید.",
    outHint: "تنظیماتی که بعد از ساخت بالانسرها و زنجیرها روی هر کانفیگ خروجی اعمال می‌شود. تا خودتان روشن نکنید همه خاموش است.",
    outEnabled: "تنظیمات خروجی اعمال شود", outWhen: "فقط برای کانفیگ‌های مطابق",
    sectInbounds: "اینباند و مسیریابی", sectDns: "DNS", sectTuning: "تنظیم بالانسرها", sectRemark: "نام‌ها",
    splitInbounds: "اینباند socks و http جدا باشد (بعضی برنامه‌ها با اینباند ترکیبی کار نمی‌کنند)",
    dnsOut: "خروجی dns-out اضافه شود", blockUdp: "پورت UDP 443 (QUIC) بسته شود تا برنامه‌ها به TCP برگردند",
    quicEdit: "کپی فهرست داخلی برای ویرایش",
    sniffOver: "Sniffing: destOverride", sniffHint: "پروتکل‌هایی که اینباندهای socks و http شناسایی می‌کنند (پیش‌فرض: http, tls, quic, fakedns).", routeOnly: "Sniffing routeOnly", socksPort: "پورت socks (خالی = همان پنل)", httpPort: "پورت http (خالی = همان پنل)",
    profile: "پروفایل", profileDefaultNote: "پروفایل پیش‌فرض را نمی‌شود تغییر نام داد یا حذف کرد. برای مدیریت، پروفایل دیگری را از بالای صفحه انتخاب کن.", profileManageNote: "پروفایل {n}: تغییر نام یا حذف (فایلش به profiles/trash/ منتقل می‌شود و پاک نمی‌شود).", profileDefault: "پروفایل پیش‌فرض", profileNew: "+ پروفایل جدید", profileName: "نام پروفایل جدید (حروف کوچک انگلیسی، عدد، - یا _)", profileCopy: "از روی نسخهٔ پروفایل فعلی شروع شود (حساب‌ها کپی نمی‌شوند)؟ تأیید = کپی، لغو = خالی", profileRestart: "انجام شد. سرویس را ری‌استارت کن تا مسیرها هماهنگ شوند.", profileRename: "تغییر نام", profileRemove: "حذف", profileDelete: "پروفایل {n} حذف شود؟ فایلش به profiles/trash/ منتقل می‌شود و پاک نمی‌شود.",
    quicDomains: "دامنه‌های QUIC (خالی = فهرست داخلی)", replaceRouting: "قوانین مسیریابی با قوانین ساخته‌شده در اینجا جایگزین شوند (قوانین بالانسر می‌مانند)",
    domainStrategy: "استراتژی دامنه", baseRules: "قوانین پایهٔ مسیریابی", baseOff: "خاموش", baseBuiltin: "داخلی (آی‌پی خصوصی و سایت‌های ایران مستقیم)", baseCustom: "فهرست دلخواه",
    baseRulesList: "قوانین (فهرست JSON)", baseRulesHint: "قوانینی که به هر کانفیگ اضافه می‌شوند؛ مجموعهٔ داخلی آی‌پی‌های خصوصی و سایت‌های ایرانی را مستقیم می‌کند.",
    dedicatedDns: "DNS اختصاصی برای دامنه‌های خود پروکسی‌ها", ddIp: "آی‌پی سرور DNS", ddTag: "تگ",
    directDns: "دامنه‌های داخلی با DNS داخلی حل شوند", ddRegex: "الگوی تگ DNS داخلی (regex)",
    samplingTitle: "نمونه‌گیری observatory", samplingOff: "خاموش (دست نخورد)", samplingFixed: "عدد ثابت", samplingDiv: "بر اساس تعداد اعضا",
    samplingFixedN: "تعداد نمونه", samplingDivN: "تعداد عضو به‌ازای هر نمونه", samplingExtra: "نمونهٔ اضافه",
    panelBal: "بالانسرهای خود پنل هم تنظیم شوند", pbRtt: "حداکثر RTT", pbFew: "«کم» یعنی حداکثر این تعداد عضو", pbExpFew: "expected (عضو کم)", pbExpMany: "expected (عضو زیاد)",
    remarkTitle: "بازنویسی نام‌ها", remarkHint: "هر قانون متنِ مطابق با الگو را عوض می‌کند. اگر «فقط اگر» پر باشد، نام باید با آن هم بخواند تا قانون اجرا شود.",
    rwRegex: "الگو", rwReplace: "جایگزین", rwIf: "فقط اگر نام بخواند با", addRule: "+ افزودن قانون",
    usingDefaults: "مقدارهای داخلی استفاده می‌شود.", customize: "سفارشی‌سازی",
    orWord: "یا", notWord: "نه",
    chainMode: "جهت", modeEntry: "ورودی اول: خروجی شما از داخل کانفیگ پنل رد می‌شود", modeExit: "خروجی اول: خروجی از ورودی شما رد می‌شود (مثلاً کلاینت ← WARP ← خروجی)",
    chainEndpoints: "Endpoints", chainEndpointsHint: "متن با جایگزین، مثلاً {account.masque.endpoints}؛ آدرس و پورت ورودی.",
    chainPick: "انتخاب", pickRandom: "هر بار تصادفی", pickUser: "برای هر کاربر ثابت",
    chainExit: "خروجی (JSON)", chainExitHint: "false = بدون کانفیگ خروجی (تکی). یا {\"from_account\": \"exits\", \"default_account\": \"exit\", \"user_id\": true}.",
    chainEntryMerge: "ادغام در ورودی (JSON)", chainEntryMergeHint: "در outbound ورودی ادغام می‌شود؛ جایگزین‌های {account.x?} اگر مقدار نداشته باشند حذف می‌شوند.",
    chainBefore: "outboundهایی که جلو قرار می‌گیرند (فهرست JSON)", chainBeforeHint: "جایگزین‌ها: {entry.address}، {entry.port}، {user.id}.",
    expandTitle: "کپی به‌ازای هر سرور", expandOn: "از هر سرور چند کپی ساخته شود (با آدرس‌های مختلف)",
    exCopies: "تعداد کپی", exServerBy: "فیلد کلید سرور", exServerRegex: "regex کلید سرور", exAddresses: "آدرس‌های مورد استفاده", exAddrRegex: "اگر آدرس خودش با این بخواند نگه داشته شود",
    exLayout: "چیدمان", exGrouped: "گروهی", exBlocks: "بلوکی (چرخش در هر بلوک)", exPick: "انتخاب", exWhen: "فقط برای اعضای مطابق",
    includeBalanced: "کانفیگ‌هایی که از قبل بالانسر هستند هم استفاده شوند",
    memberPosition: "جای اعضا (فهرست JSON)", memberPositionHint: "[{\"when\": {...}, \"at\": \"first\"|\"last\"}]",
    catchall: "قوانین catch-all (فهرست JSON)", catchallHint: "قوانین مسیریابی که به این بالانسر می‌روند؛ تگ بالانسر خودکار پر می‌شود.",
    memberPatch: "پچ اعضا (فهرست JSON)", memberPatchHint: "[{\"when\": {...}, \"merge\": {...}, \"random\": {...}}]",
  });

  Object.assign(STR.en, {
    tabList: "What users get", tabGroups: "Balancers", tabWarp: "WARP", tabSettings: "Settings", tabAdvanced: "Advanced",
    sectFilter: "Remove or keep configs", sectSort: "Sort the list", sectServer: "Server, panel and accounts", sectOutput: "Final output settings",
    sectPatches: "Advanced edits (patches)", sectJson: "Whole config as JSON", moreOptions: "More options", unnamed: "(no name)",
    rulesHint: "Rules run from top to bottom; the first match decides.",
    groupsHint: "Merge several configs into one smart config that picks the best server by itself.",
    chainsHint: "Send traffic through a second hop such as WARP.",
    patchesHint: "For experts: merge your own JSON into the configs. A null value deletes a key.",
    orderHint: "The first matching rule gives a config its rank; lower ranks come first.",
    addFrom: "+ Add…", tpl_blank: "Empty (fill in yourself)",
    tpl_rule_name: "Remove configs whose name contains…", tpl_rule_proto: "Remove configs of a protocol…", tpl_rule_top: "Move configs whose name contains… to the top",
    tpl_group_flag: "Merge matching configs into one per country", tpl_group_all: "Merge matching configs into a single balancer",
    tpl_chain_warp: "Send through WARP (client → WARP → config)", tpl_order_name: "Put configs whose name contains… first",
    sum_group: "{when} → merged into a smart config «{name}»", sum_group_split: "{when} → one smart config «{name}» per group",
    sum_chain_entry: "For configs where {when}: your outbound is dialed through them", sum_chain_exit: "For configs where {when}: client → entry → that config",
    offWord: "off", previewHint: "Enter a user's subscription id to see what that user gets.",
  });
  Object.assign(STR.fa, {
    tabList: "آنچه کاربر می‌گیرد", tabGroups: "بالانسرها", tabWarp: "WARP", tabSettings: "تنظیمات", tabAdvanced: "پیشرفته",
    sectFilter: "حذف یا نگه‌داشتن کانفیگ‌ها", sectSort: "ترتیب لیست", sectServer: "سرور، پنل و حساب‌ها", sectOutput: "تنظیمات خروجی نهایی",
    sectPatches: "ویرایش پیشرفته (پچ)", sectJson: "کل تنظیمات به‌صورت JSON", moreOptions: "گزینه‌های بیشتر", unnamed: "(بدون نام)",
    rulesHint: "قانون‌ها از بالا به پایین بررسی می‌شوند؛ اولین قانونِ مطابق تصمیم می‌گیرد.",
    groupsHint: "چند کانفیگ را در یک کانفیگ هوشمند ادغام می‌کند که خودش بهترین سرور را برمی‌گزیند.",
    chainsHint: "ترافیک را از یک مسیر دوم مثل WARP عبور می‌دهد.",
    patchesHint: "برای کاربران حرفه‌ای: JSON خودتان را در کانفیگ‌ها ادغام کنید. مقدار null کلید را حذف می‌کند.",
    orderHint: "اولین قانونِ مطابق به کانفیگ رتبه می‌دهد؛ رتبهٔ کمتر زودتر می‌آید.",
    addFrom: "+ افزودن…", tpl_blank: "خالی (خودم پر می‌کنم)",
    tpl_rule_name: "حذف کانفیگ‌هایی که نامشان شامل … است", tpl_rule_proto: "حذف کانفیگ‌های یک پروتکل…", tpl_rule_top: "کانفیگ‌هایی که نامشان شامل … است بالا بروند",
    tpl_group_flag: "کانفیگ‌های مطابق به‌ازای هر کشور در یکی ادغام شوند", tpl_group_all: "کانفیگ‌های مطابق در یک بالانسر ادغام شوند",
    tpl_chain_warp: "عبور از WARP (کلاینت ← WARP ← کانفیگ)", tpl_order_name: "کانفیگ‌هایی که نامشان شامل … است اول بیایند",
    sum_group: "{when} ← ادغام در کانفیگ هوشمند «{name}»", sum_group_split: "{when} ← یک کانفیگ هوشمند «{name}» به‌ازای هر گروه",
    sum_chain_entry: "برای کانفیگ‌هایی که {when}: خروجی شما از داخل آن‌ها رد می‌شود", sum_chain_exit: "برای کانفیگ‌هایی که {when}: کلاینت ← ورودی ← آن کانفیگ",
    offWord: "خاموش", previewHint: "شناسهٔ ساب یک کاربر را بگذارید تا ببینید آن کاربر چه می‌گیرد.",
  });
  Object.assign(STR.en, {
    rowAdvanced: "Advanced (pattern, numbers…)", rowSimple: "Switch to simple", notPlain: "This pattern has no simple form.",
    addWordPh: "Type a word, press Enter", ciLabel: "Ignore upper/lower case", ciShort: "any case", suggestFrom: "From your subscription:",
    condMatches: "Matches {n} of {m} configs in your sample.", condNoSample: "Load your subscription in Preview to see how many configs match and to pick values from it.",
    condInvalid: "This condition is not complete or not valid yet.",
    themeDark: "Dark", themeLight: "Light", themeTitle: "Switch between light and dark",
    sectPanelConn: "3x-ui panel connection", sectSubServer: "Subscription server", sectAccountsWarp: "Accounts and WARP",
    panelConnHint: "Where XraySubForge reads the panel's JSON subscription from.", httpsTitle: "HTTPS",
    httpsHint: "Fill these in only if this service itself serves HTTPS. Leave them empty when a reverse proxy does it.",
    sp_title_group: "Make one balancer for each…", sp_title_chain: "Make one chain for each…",
    sp_none_group: "Nothing: all matching configs go into one balancer", sp_none_chain: "Nothing: one chain, from the first matching config",
    sp_flag: "Country (the flag in the name)", sp_field: "Value of a field…", sp_word: "First word of the name",
    sp_after: "Part of the name after a text…", sp_regex: "Custom pattern (advanced)", sp_fieldPick: "Field",
    sp_afterText: "After this text", sp_afterHint: "Example: in \"fast-berlin-1\", the text \"fast-\" and the character \"-\" give \"berlin\".",
    sp_untilChar: "Up to this character (optional)", sp_untilHint: "Empty = up to the end of the name",
    renameItem: "Rename", renameHint: "The technical name stored in config.json. Changing it changes only how this item is named.",
  });
  Object.assign(STR.fa, {
    rowAdvanced: "پیشرفته (الگو، عدد، …)", rowSimple: "برگشت به حالت ساده", notPlain: "This pattern has no simple form.",
    addWordPh: "کلمه را بنویسید و اینتر بزنید", ciLabel: "بدون حساسیت به حروف بزرگ و کوچک", ciShort: "بدون حساسیت به حروف", suggestFrom: "از ساب شما:",
    condMatches: "روی {n} کانفیگ از {m} کانفیگ نمونه می‌خورد.", condNoSample: "برای دیدن اینکه شرط روی چند کانفیگ می‌خورد و برای انتخاب مقدارها، ساب خود را در «پیش‌نمایش» بارگذاری کنید.",
    condInvalid: "این شرط هنوز کامل یا معتبر نیست.",
    themeDark: "تیره", themeLight: "روشن", themeTitle: "تغییر بین حالت روشن و تیره",
    sectPanelConn: "اتصال به پنل 3x-ui", sectSubServer: "سرور ساب", sectAccountsWarp: "حساب‌ها و WARP",
    panelConnHint: "آدرسی که XraySubForge ساب JSON پنل را از آن می‌خواند.", httpsTitle: "HTTPS",
    httpsHint: "این دو را فقط وقتی پر کنید که خود این سرویس HTTPS بدهد. اگر reverse proxy این کار را می‌کند، خالی بگذارید.",
    sp_title_group: "یک بالانسر جدا برای هر…", sp_title_chain: "یک زنجیرهٔ جدا برای هر…",
    sp_none_group: "هیچ‌کدام: همهٔ کانفیگ‌های مطابق در یک بالانسر", sp_none_chain: "هیچ‌کدام: یک زنجیره از اولین کانفیگ مطابق",
    sp_flag: "کشور (پرچم در نام)", sp_field: "مقدار یک فیلد…", sp_word: "کلمهٔ اول نام",
    sp_after: "بخشی از نام بعد از یک متن…", sp_regex: "الگوی دلخواه (پیشرفته)", sp_fieldPick: "فیلد",
    sp_afterText: "بعد از این متن", sp_afterHint: "مثال: در «fast-berlin-1» متن «fast-» و نویسهٔ «-» می‌شود «berlin».",
    sp_untilChar: "تا این نویسه (اختیاری)", sp_untilHint: "خالی = تا آخر نام",
    renameItem: "تغییر نام", renameHint: "نام فنی ذخیره‌شده در config.json. تغییرش فقط نام این مورد را عوض می‌کند.",
  });
  Object.assign(STR.en, {
    tabBlocks: "Blocks", bFromPanel: "From your panel", bKindsN: "{n} configs · {k} kinds",
    bSourceHint: "Similar configs are grouped into kinds, so a block keeps working for every user and for servers added later. Drag a kind into a block, or press Pick and then Move here.",
    bNoSample: "Fetch a user's subscription in the Preview panel (on the right) to see your configs here.",
    bFinal: "Final subscription", bFinalHint: "Blocks run from top to bottom. A kind is in one list (or removed); several balancers may use the same kinds.",
    sourceLabel: "Where the configs come from", sourceJson: "The panel's JSON subscription", sourceRaw: "The panel's raw links (JSON is built here)",
    sourceHint: "With raw links you do not need the JSON subscription in 3x-ui; set the raw subscription URL above. vless, vmess, trojan and ss links are read; masque, hysteria2, tuic and wireguard are left out.",
    rawModeLabel: "Raw link for users", rawPass: "The panel's links, unchanged", rawEngine: "With my rules and blocks",
    rawModeHint: "Links carry fewer settings than JSON: balancers become their members, and fragment or cipher suites are left out.",
    rawWarn: "The JSON subscription is the better source: it carries everything the panel knows (its DNS and routing, the hosts' fragment / Final Mask, mux, sockopt and more). Links carry only part of it, so those settings are lost unless you add them again here, and some types (masque, hysteria2, tuic, wireguard) are not read at all. Use raw links only when you cannot turn the JSON subscription on.",
    versionTitle: "The version of this panel (and the git commit, for a git checkout)",
    jsonTemplate: "Client config for links (JSON)", jsonTemplateHint: "Raw links only: inbounds, DNS and routing each built config gets. Empty = a built-in one.",
    bSelHint: "Ctrl/Cmd+click selects several, Shift+click a range; drag them together or use Move here.", bSelN: "{n} selected", bSelClear: "Clear", bNotPlaced: "not placed yet", bIn: "in {b}", bRemovedWhere: "removed", bPick: "Pick", bPicked: "Picked", bMoveHere: "Move here",
    bDropHere: "Drop kinds here", bList: "List", bBalancer: "Balancer", bPerCountry: "One per country",
    bUp: "Move block up", bDown: "Move block down", bDelete: "Delete block", bTakeOut: "Take out of this block", bBlockName: "Block name",
    bAddList: "+ List block", bAddBalancer: "+ Balancer per country", bNewBlock: "Block {n}", bNewBalancer: "Balancer {n}",
    bRest: "Everything else", bRestHint: "Kinds no block has taken. New inbounds you add later land here, so nothing gets lost unnoticed.",
    bKeepEnd: "At the end", bKeepTop: "At the top", bHide: "Hide", bRestEmpty: "Nothing left over.",
    bRemoved: "Removed", bRemovedHint: "Drop a kind here to take it out of everyone's subscription.", bRemove: "Remove", bBringBack: "Bring back",
    bUndo: "Undo", bRedo: "Redo", bAddSetting: "+ Setting", bAllSettings: "Every setting for this block is already added.",
    bDefault: "Back to default", bRandom: "random", bAddCustom: "Add custom", bAddAddress: "Add address",
    bCustomFrag: "Your own: packets, lengths, delays (e.g. tlshello, 10-20, 1)", bCustomCipher: "Your own list: TLS_…:TLS_…", bAddressPh: "Address or domain",
    bAddresses: "{n} addresses", bExample: "Example: {x}",
    pMerge: "Merge", pRoutePre: "Routing rules added first", pRoutePost: "Routing rules added last",
    s_choices: "Choices", h_choices: "Lists of values; each user gets one value of each list (the same one every time), available as {choice.name} in the entry.", chName: "name", chValues: "values, separated by commas", chAdd: "+ List",
    s_entry: "Entry outbound", h_entry: "The outbound dialed through the exit: a {account.x} placeholder, or the outbound itself.", entryText: "placeholder", entryObj: "outbound (path = value)",
    s_endpoints: "Endpoints", h_endpoints: "Addresses the entry connects to (host:port, one per user), or one {account.x} placeholder.",
    s_patches: "Patches", h_patches: "Changes for this block's configs: merge values, or add routing rules before / after the existing ones.", bNPatches: "{n} patches", bNLists: "{n} lists",
    s_min_members: "Minimum members", h_min_members: "A balancer is built only when it would have at least this many members; otherwise its configs stay as they were.",
    s_keep_members: "Keep single configs", h_keep_members: "Keep the original single configs next to the balancer instead of replacing them.", bKeepMembers: "kept next to the balancer",
    s_include_balanced: "Include panel balancers", h_include_balanced: "Also use configs that already have a balancer of the panel's own.", bIncludeBalanced: "included",
    s_probe_kind: "Probe type", h_probe_kind: "Which Xray probe measures the members. Default: burstObservatory for leastLoad, observatory for the others.",
    s_position: "Position", h_position: "Put the result at the top or the bottom of the subscription, whatever the block order says.", bPosTop: "top", bPosBottom: "bottom",
    s_remove_exit: "Remove the exit config", h_remove_exit: "Take the config the WARP chain starts from out of the result.", bRemoveExit: "removed",
    s_expand: "Copies per server", h_expand: "Several members per server: one copy of each config per address, grouped by server. Replaces the plain address pool.",
    s_entry_merge: "Entry changes", h_entry_merge: "Values merged into the WARP entry outbound, e.g. sockopt or the account's keys ({account.privateKey?}).",
    kvPath: "path (a.b.c)", kvValue: "value", kvAdd: "+ Value", kvHint: "A value is JSON when it parses (true, 5, null, [..]); otherwise text. null deletes the key.",
    bRule: "Rule", bRuleAdd: "+ Rule", bRuleKept: "Also kept as they are: {k}", bExpandSum: "{n} copies", bNPaths: "{n} values",
    s_member_position: "Member order", h_member_position: "Where matching configs sit inside the balancer. The first rule that matches a config decides.",
    s_member_patch: "Member patches", h_member_patch: "Changes applied to every config that joins this balancer (for example alpn or sockopt). Patches run in order.",
    s_catchall_rules: "Catch-all rules", h_catchall_rules: "The routing rules sent to the balancer, in this order (JSON list; the balancer tag is filled in). Default: tcp and udp.",
    bMoveAdv: "Move to settings", bMoveAdvHint: "Parameters, probe, cost, member order, catch-all rules and member patches have settings of their own. Moving them changes nothing in the result.",
    bNSteps: "{n} patches", bNRules: "{n} rules", bPosAt: "position", bPos_first: "first", bPos_last: "last", bPosAdd: "+ Order rule",
    s_fragment: "Fragment", s_cipher: "Cipher suites", s_fingerprint: "Fingerprint", s_strategy: "Strategy", s_pool: "Address pool", s_name: "Name",
    h_fragment: "Pick one or more. With several, each config gets one of them at random.",
    h_cipher: "Pick one or more. With several, each config gets one of them at random. TLS configs only.",
    h_fingerprint: "The browser the TLS handshake looks like.", h_strategy: "How the balancer picks a member.",
    h_pool: "Each member gets one copy per address. Click an address to take it out.", h_name: "What users see in their app.",
    bCustom: "custom", bOtherCond: "condition",
    bTakes: "Takes {n} configs of this sample", bAdvancedKept: "Some settings of the old balancer are kept as they were (Advanced).",
    bClassicTitle: "Made in the old tabs", bClassicHint: "These still work as before. Convert one to a block to edit it here; the old item is switched off, not deleted (Undo brings it back).",
    bOldBalancer: "balancer", bOldDrop: "removes", bOldRule: "rule", bOldWarp: "WARP chain", bConvert: "Convert to block", bOpenOld: "Open",
    bTakesNothing: "Takes no config of this sample.", bNoSampleShort: "Fetch a subscription to see what it takes.", bOldCond: "condition of {id}",
    advRules: "Rules and order", advPatches: "Patches", advJson: "JSON",
    bWarp: "WARP", bAddWarp: "+ WARP block", bNewWarp: "WARP {n}", s_warp: "Route", s_pick: "WARP endpoint",
    h_warp: "WARP, then the exit server of the config; or WARP alone.", h_pick: "Which WARP endpoint each user gets.",
    bCostTitle: "Cost per member", bCostHint: "The first rule that matches a config sets its cost (higher = chosen less often). A rule without a condition is the default.", bCostValue: "cost", bCostWhen: "when", bCostAdd: "+ Cost rule", bCostAll: "every other config",
    bLoadParams: "leastLoad parameters (empty = Xray default)", bProbeParams: "Probe (how members are measured)", bNoParams: "This strategy has no parameters.", s_load: "leastLoad parameters", h_load: "expected, maxRTT and tolerance of the leastLoad strategy. Empty fields use Xray's own defaults.", s_probe: "Probe", h_probe: "How the balancer measures its members: URL, method, interval, number of samples and timeout.",
    s_decoy: "Decoy outbound", h_decoy: "With WARP only: an unused vless+TLS outbound in front, so apps that refuse a lone masque config load it.", bDecoyVless: "vless + TLS (unused)", bWarpExit: "WARP, then the exit", bWarpOnly: "WARP only", bPickRandom: "random on every update", bPickUser: "fixed per user",
    bAdvancedJson: "Advanced (JSON)", bAdvBalancer: "\"group\": extra balancer keys (params, probe, expand, …); \"member_patch\": extra steps for every member.",
    bAdvList: "\"patches\": a list of patches (merge, random, routing_prepend, …) applied to this block's configs.",
    bAdvWarp: "\"chain\": extra chain keys (entry, endpoints, exit, entry_merge, before, …).",
    domainsTitle: "More domains", domainsHint: "Each domain gets its own certificate, chosen by the name the app connects to (for example one behind Cloudflare with Cloudflare's Origin certificate, one behind another CDN). Point every domain at this server. Needs a restart.",
    dom_name: "Domain", dom_cert: "Certificate (fullchain)", dom_key: "Private key", domainAdd: "+ Domain",
    cancel: "Cancel", bEditCond: "Edit this condition", bDone: "Done", bDragBlock: "Drag to move this block",
    sumTitle: "Save these changes?", sumNothing: "No visible changes.", sumBlockAdded: "New block: {x}", sumBlockChanged: "Changed block: {x}",
    sumBlockRemoved: "Deleted block: {x}", sumRest: "\"Everything else\" changed", sumOldAdded: "New item in the old tabs: {x}",
    sumOldOff: "Switched off (now a block): {x}", sumOldChanged: "Changed in the old tabs: {x}", sumOldRemoved: "Deleted from the old tabs: {x}",
    sumSettings: "Settings changed: {x}", sumChecking: "Checking your sample…", sumNoSample: "Fetch a subscription in Preview to see the effect before saving.",
    sumImpact: "Your sample: {n} configs from the panel; users got {a}, after saving they get {b}.", sumErrors: "{n} problem(s)",
    bTestUsers: "Test on users", bTestPh: "Subscription ids, one per line (up to 10)",
    bTestHint: "Runs the current, unsaved settings on these users' real subscriptions. The ids are not stored anywhere.",
    bTestRun: "Run the test", bTestRow: "{id}: {a} configs → {b} · {u} not placed in any block", bTestErr: "{id}: {e}",
    bCleanOld: "Delete switched-off old items ({n})", bNewCond: "New condition", bAddCond: "Add", bPlusCond: "+ Condition",
  });
  Object.assign(STR.fa, {
    tabBlocks: "بلوک‌ها", bFromPanel: "از پنل شما", bKindsN: "{n} کانفیگ · {k} گونه",
    bSourceHint: "کانفیگ‌های مشابه یک «گونه» می‌شوند تا بلوک برای همهٔ کاربران و سرورهای بعدی هم کار کند. گونه را داخل یک بلوک بکشید، یا «انتخاب» و بعد «انتقال به اینجا» را بزنید.",
    bNoSample: "برای دیدن کانفیگ‌ها، ساب یک کاربر را در پنل پیش‌نمایش (سمت دیگر) بگیرید.",
    bFinal: "اشتراک نهایی", bFinalHint: "بلوک‌ها از بالا به پایین اجرا می‌شوند. هر گونه در یک فهرست است (یا حذف‌شده)؛ چند بالانسر می‌توانند از یک گونه استفاده کنند.",
    sourceLabel: "کانفیگ‌ها از کجا بیایند", sourceJson: "ساب JSON پنل", sourceRaw: "لینک‌های خام پنل (JSON همین‌جا ساخته می‌شود)",
    sourceHint: "با لینک‌های خام لازم نیست ساب JSON را در 3x-ui روشن کنید؛ آدرس ساب خام را بالا بگذارید.",
    rawWarn: "ساب JSON منبع بهتری است: هر چیزی که پنل می‌داند را دارد (DNS و routing پنل، fragment / Final Mask هاست‌ها، mux، sockopt و بیشتر). لینک‌ها فقط بخشی از این‌ها را دارند، پس آن تنظیمات از دست می‌روند مگر اینکه اینجا دوباره اضافه‌شان کنید، و بعضی نوع‌ها (masque، hysteria2، tuic، wireguard) اصلاً خوانده نمی‌شوند. لینک خام را فقط وقتی انتخاب کنید که نمی‌توانید ساب JSON را روشن کنید.",
    rawModeLabel: "لینک خام برای کاربران", rawPass: "لینک‌های پنل، بدون تغییر", rawEngine: "با قوانین و بلوک‌های من",
    rawModeHint: "لینک‌ها تنظیمات کمتری از JSON دارند: بالانسر به اعضایش تبدیل می‌شود و fragment و cipher suites حذف می‌شوند.",
    bSelHint: "Ctrl/Cmd+کلیک چند مورد و Shift+کلیک یک بازه را انتخاب می‌کند؛ با هم بکشید یا «انتقال به اینجا» بزنید.", bSelN: "{n} انتخاب شد", bSelClear: "پاک کردن", bNotPlaced: "هنوز جایی نیست", bIn: "در {b}", bRemovedWhere: "حذف‌شده", bPick: "انتخاب", bPicked: "انتخاب شد", bMoveHere: "انتقال به اینجا",
    bDropHere: "گونه‌ها را اینجا رها کنید", bList: "فهرست", bBalancer: "بالانسر", bPerCountry: "یکی برای هر کشور",
    bUp: "بالا بردن بلوک", bDown: "پایین بردن بلوک", bDelete: "حذف بلوک", bTakeOut: "بیرون آوردن از این بلوک", bBlockName: "نام بلوک",
    bAddList: "+ بلوک فهرست", bAddBalancer: "+ بالانسر هر کشور", bNewBlock: "بلوک {n}", bNewBalancer: "بالانسر {n}",
    bRest: "بقیه", bRestHint: "گونه‌هایی که هیچ بلوکی برنداشته. inbound‌های تازه هم اینجا می‌آیند تا چیزی بی‌خبر گم نشود.",
    bKeepEnd: "در انتها", bKeepTop: "در ابتدا", bHide: "پنهان شوند", bRestEmpty: "چیزی باقی نمانده.",
    bRemoved: "حذف‌شده", bRemovedHint: "گونه را اینجا رها کنید تا از ساب همه حذف شود.", bRemove: "حذف", bBringBack: "برگرداندن",
    bUndo: "واگرد", bRedo: "ازنو", bAddSetting: "+ تنظیم", bAllSettings: "همهٔ تنظیم‌های این بلوک اضافه شده‌اند.",
    bDefault: "برگشت به پیش‌فرض", bRandom: "تصادفی", bAddCustom: "افزودن دلخواه", bAddAddress: "افزودن آدرس", bAddressPh: "آدرس یا دامنه",
    bAddresses: "{n} آدرس", bExample: "نمونه: {x}",
    h_fragment: "یکی یا چند تا را انتخاب کنید. با چند تا، هر کانفیگ یکی را تصادفی می‌گیرد.",
    h_cipher: "یکی یا چند تا را انتخاب کنید. با چند تا، هر کانفیگ یکی را تصادفی می‌گیرد. فقط کانفیگ‌های TLS.",
    h_fingerprint: "دست‌دادن TLS شبیه کدام مرورگر باشد.", h_strategy: "بالانسر عضو را چطور انتخاب کند.",
    h_pool: "هر عضو برای هر آدرس یک کپی می‌گیرد. روی آدرس بزنید تا حذف شود.", h_name: "نامی که کاربر در اپ می‌بیند.",
    bCustom: "دلخواه", bOtherCond: "شرط",
    bTakes: "{n} کانفیگ از این نمونه را برمی‌دارد", bAdvancedKept: "بخشی از تنظیمات بالانسر قدیمی همان‌طور که بود نگه داشته شده (پیشرفته).",
    bClassicTitle: "ساخته‌شده در تب‌های قدیمی", bClassicHint: "این‌ها مثل قبل کار می‌کنند. برای ویرایش در اینجا به بلوک تبدیلشان کنید؛ مورد قدیمی خاموش می‌شود، نه پاک (با واگرد برمی‌گردد).",
    bOldBalancer: "بالانسر", bOldDrop: "حذف", bOldRule: "قانون", bOldWarp: "زنجیرهٔ WARP", bConvert: "تبدیل به بلوک", bOpenOld: "باز کردن",
    bTakesNothing: "هیچ کانفیگی از این نمونه را برنمی‌دارد.", bNoSampleShort: "برای دیدن، یک ساب بگیرید.", bOldCond: "شرط {id}",
    advRules: "قوانین و ترتیب", advPatches: "پچ‌ها", advJson: "JSON",
    bAddWarp: "+ بلوک WARP", bNewWarp: "WARP {n}", s_warp: "مسیر", s_pick: "endpoint وارپ",
    h_warp: "اول WARP، بعد سرور خروجی کانفیگ؛ یا فقط WARP.", h_pick: "هر کاربر کدام endpoint وارپ را بگیرد.",
    bCostTitle: "Cost هر عضو", bCostHint: "اولین قانونی که با یک کانفیگ جور شود cost آن را تعیین می‌کند (بیشتر = کمتر انتخاب می‌شود). قانون بدون شرط، پیش‌فرض است.", bCostValue: "cost", bCostWhen: "شرط", bCostAdd: "+ قانون cost", bCostAll: "بقیهٔ کانفیگ‌ها",
    pMerge: "ادغام", pRoutePre: "قوانین مسیریابی که اول اضافه می‌شوند", pRoutePost: "قوانین مسیریابی که آخر اضافه می‌شوند",
    s_choices: "Choices", h_choices: "لیست‌هایی از مقدار؛ هر کاربر از هر لیست یک مقدار می‌گیرد (همیشه همان) و در entry به شکل {choice.name} قابل استفاده است.", chName: "نام", chValues: "مقدارها، با ویرگول جدا شوند", chAdd: "+ لیست",
    s_entry: "Entry outbound", h_entry: "outbound که از طریق خروج وصل می‌شود: یک placeholder مثل {account.x} یا خود outbound.", entryText: "placeholder", entryObj: "outbound (مسیر = مقدار)",
    s_endpoints: "Endpoints", h_endpoints: "آدرس‌هایی که entry به آن‌ها وصل می‌شود (host:port، برای هر کاربر یکی) یا یک placeholder مثل {account.x}.",
    s_patches: "Patches", h_patches: "تغییرات برای کانفیگ‌های این بلوک: ادغام مقدار، یا افزودن قانون مسیریابی قبل / بعد از قوانین موجود.", bNPatches: "{n} patch", bNLists: "{n} لیست",
    s_min_members: "حداقل اعضا", h_min_members: "بالانسر فقط وقتی ساخته می‌شود که دست‌کم این تعداد عضو داشته باشد؛ وگرنه کانفیگ‌ها همان‌طور می‌مانند.",
    s_keep_members: "نگه‌داشتن کانفیگ‌های تکی", h_keep_members: "کانفیگ‌های تکی اصلی کنار بالانسر می‌مانند و جایگزین نمی‌شوند.", bKeepMembers: "کنار بالانسر می‌ماند",
    s_include_balanced: "شامل بالانسرهای پنل", h_include_balanced: "کانفیگ‌هایی که از قبل بالانسر خود پنل را دارند هم استفاده می‌شوند.", bIncludeBalanced: "شامل",
    s_probe_kind: "نوع probe", h_probe_kind: "کدام probe ایکس‌ری اعضا را اندازه بگیرد. پیش‌فرض: burstObservatory برای leastLoad و observatory برای بقیه.",
    s_position: "جایگاه", h_position: "نتیجه بالا یا پایین اشتراک قرار بگیرد، فارغ از ترتیب بلوک‌ها.", bPosTop: "بالا", bPosBottom: "پایین",
    s_remove_exit: "حذف کانفیگ خروج", h_remove_exit: "کانفیگی که زنجیرهٔ WARP از آن شروع می‌شود از نتیجه حذف می‌شود.", bRemoveExit: "حذف می‌شود",
    s_expand: "Copies per server", h_expand: "چند عضو برای هر سرور: از هر کانفیگ به ازای هر آدرس یک کپی، گروه‌بندی‌شده بر اساس سرور. جایگزین Address pool ساده می‌شود.",
    s_entry_merge: "تغییرات Entry", h_entry_merge: "مقادیری که در outbound ورودی WARP ادغام می‌شوند، مثل sockopt یا کلیدهای حساب ({account.privateKey?}).",
    kvPath: "مسیر (a.b.c)", kvValue: "مقدار", kvAdd: "+ مقدار", kvHint: "مقدار اگر JSON معتبر باشد (true، 5، null، [..]) همان است، وگرنه متن. null کلید را حذف می‌کند.",
    bRule: "قانون", bRuleAdd: "+ قانون", bRuleKept: "این‌ها هم همان‌طور نگه داشته می‌شوند: {k}", bExpandSum: "{n} کپی", bNPaths: "{n} مقدار",
    s_member_position: "ترتیب اعضا", h_member_position: "جای کانفیگ‌های جورشده داخل بالانسر. اولین قانونی که با کانفیگ جور شود تعیین می‌کند.",
    s_member_patch: "Patch اعضا", h_member_patch: "تغییراتی که روی هر کانفیگ عضو این بالانسر اعمال می‌شود (مثلاً alpn یا sockopt). به ترتیب اجرا می‌شوند.",
    s_catchall_rules: "قوانین Catch-all", h_catchall_rules: "قوانین مسیریابی که به بالانسر می‌روند، به همین ترتیب (لیست JSON؛ تگ بالانسر خودکار پر می‌شود). پیش‌فرض: tcp و udp.",
    bMoveAdv: "انتقال به Settings", bMoveAdvHint: "پارامترها، probe، cost، ترتیب اعضا، قوانین catch-all و patchهای اعضا Setting خودشان را دارند. انتقال، نتیجه را تغییر نمی‌دهد.",
    bNSteps: "{n} patch", bNRules: "{n} قانون", bPosAt: "جایگاه", bPos_first: "اول", bPos_last: "آخر", bPosAdd: "+ قانون ترتیب",
    bLoadParams: "پارامترهای leastLoad (خالی = پیش‌فرض Xray)", bProbeParams: "Probe (نحوهٔ اندازه‌گیری اعضا)", bNoParams: "این استراتژی پارامتری ندارد.", s_load: "پارامترهای leastLoad", h_load: "expected و maxRTT و tolerance در استراتژی leastLoad. فیلد خالی = پیش‌فرض Xray.", s_probe: "Probe", h_probe: "نحوهٔ اندازه‌گیری اعضای بالانسر: آدرس، متد، فاصله، تعداد نمونه و timeout.",
    s_decoy: "outbound طعمه", h_decoy: "فقط با WARP تنها: یک outbound خالی vless+TLS در ابتدا می‌آید تا برنامه‌هایی که masque تنها را قبول نمی‌کنند، کانفیگ را باز کنند.", bDecoyVless: "vless + TLS (بدون استفاده)", bWarpExit: "WARP، بعد خروجی", bWarpOnly: "فقط WARP", bPickRandom: "تصادفی در هر به‌روزرسانی", bPickUser: "ثابت برای هر کاربر",
    domainsTitle: "دامنه‌های بیشتر", domainsHint: "هر دامنه گواهی خودش را دارد و بر اساس نامی که اپ به آن وصل می‌شود انتخاب می‌شود (مثلاً یکی پشت Cloudflare با گواهی Origin کلادفلر، یکی پشت یک CDN دیگر). همهٔ دامنه‌ها باید به این سرور اشاره کنند. نیاز به راه‌اندازی دوباره دارد.",
    dom_name: "دامنه", dom_cert: "گواهی (fullchain)", dom_key: "کلید خصوصی", domainAdd: "+ دامنه",
    cancel: "انصراف", bEditCond: "ویرایش این شرط", bDone: "تمام", bDragBlock: "برای جابه‌جایی بلوک بکشید",
    sumTitle: "این تغییرات ذخیره شوند؟", sumNothing: "تغییر قابل‌مشاهده‌ای نیست.", sumBlockAdded: "بلوک جدید: {x}", sumBlockChanged: "بلوک تغییرکرده: {x}",
    sumBlockRemoved: "بلوک حذف‌شده: {x}", sumRest: "«بقیه» تغییر کرد", sumOldAdded: "مورد جدید در تب‌های قدیمی: {x}",
    sumOldOff: "خاموش‌شده (حالا بلوک است): {x}", sumOldChanged: "تغییر در تب‌های قدیمی: {x}", sumOldRemoved: "حذف از تب‌های قدیمی: {x}",
    sumSettings: "تنظیمات تغییرکرده: {x}", sumChecking: "در حال بررسی نمونه…", sumNoSample: "برای دیدن اثر پیش از ذخیره، در پیش‌نمایش یک ساب بگیرید.",
    sumImpact: "نمونهٔ شما: {n} کانفیگ از پنل؛ کاربران {a} تا می‌گرفتند، بعد از ذخیره {b} تا می‌گیرند.", sumErrors: "{n} مشکل",
    bTestUsers: "امتحان روی کاربران", bTestPh: "شناسه‌های ساب، هر کدام در یک خط (حداکثر ۱۰)",
    bTestHint: "تنظیمات فعلی (ذخیره‌نشده) را روی ساب واقعی این کاربران اجرا می‌کند. شناسه‌ها جایی ذخیره نمی‌شوند.",
    bTestRun: "اجرای امتحان", bTestRow: "{id}: {a} کانفیگ ← {b} · {u} تا در هیچ بلوکی نیست", bTestErr: "{id}: {e}",
    bCleanOld: "حذف موارد قدیمی خاموش ({n})", bNewCond: "شرط جدید", bAddCond: "افزودن", bPlusCond: "+ شرط",
  });
  const OPLABEL = {
    en: { equals: "is exactly", not_equals: "is not", contains: "contains", icontains: "contains (any case)", not_contains: "does not contain",
      startswith: "starts with", endswith: "ends with", regex: "matches pattern", iregex: "matches pattern (any case)", in: "is one of", not_in: "is none of",
      exists: "exists", gt: ">", gte: "≥", lt: "<", lte: "≤" },
    fa: { equals: "دقیقاً برابر است با", not_equals: "برابر نیست با", contains: "شامل", icontains: "شامل (بدون حساسیت به حروف)", not_contains: "شامل نیست",
      startswith: "شروع می‌شود با", endswith: "تمام می‌شود با", regex: "با الگو می‌خواند", iregex: "با الگو می‌خواند (بدون حساسیت)", in: "یکی از", not_in: "هیچ‌کدام از",
      exists: "وجود دارد", gt: ">", gte: "≥", lt: "<", lte: "≤" },
  };
  const FIELDLABEL = {
    en: { remark: "name", protocol: "protocol", tag: "tag", address: "server address", port: "port", network: "transport", security: "security", sni: "SNI", host: "host", path: "path", flag: "flag" },
    fa: { remark: "نام", protocol: "پروتکل", tag: "تگ", address: "آدرس سرور", port: "پورت", network: "ترنسپورت", security: "امنیت", sni: "SNI", host: "host", path: "مسیر", flag: "پرچم" },
  };
  const opLabel = (op) => (OPLABEL[lang] && OPLABEL[lang][op]) || op;
  const fieldLabel = (f) => (FIELDLABEL[lang] && FIELDLABEL[lang][f]) || f;
  let lang = (navigator.language || "").startsWith("en") ? "en" : "fa";
  try { const saved = localStorage.getItem("xsf_lang"); if (saved === "fa" || saved === "en") lang = saved; } catch (e) { /* ignore */ }
  const t = (k, vars) => {
    let s = (STR[lang] && STR[lang][k]) || STR.en[k] || k;
    for (const [a, b] of Object.entries(vars || {})) s = s.replace("{" + a + "}", b);
    return s;
  };

  // ---------- light / dark ----------
  // null = follow the system; the header button picks a side and remembers it in this browser
  let theme = null;
  try { const saved = localStorage.getItem("xsf_theme"); if (saved === "light" || saved === "dark") theme = saved; } catch (e) { /* ignore */ }
  const systemDark = () => !!(window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches);
  const isDark = () => (theme ? theme === "dark" : systemDark());
  function applyTheme() { if (theme) document.documentElement.dataset.theme = theme; else delete document.documentElement.dataset.theme; }
  applyTheme();

  // ---------- tiny DOM helper ----------
  function h(tag, attrs, ...kids) {
    const e = document.createElement(tag);
    let later;
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === "class") e.className = v;
      else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
      else if (k === "value") later = v;
      else if (k === "checked") e.checked = !!v;
      else if (v === true) e.setAttribute(k, "");
      else if (v !== false && v != null) e.setAttribute(k, v);
    }
    for (const kid of kids.flat(Infinity)) {
      if (kid == null || kid === false) continue;
      e.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
    }
    if (later !== undefined) e.value = later;
    return e;
  }

  // ---------- state ----------
  let csrf = "";
  let cfg = {};
  let savedSnapshot = "{}";
  let loadedRoute = "/sub/";
  let canRestart = false;
  let appVersion = "";
  // the selected profile lives in the address (?profile=name), so a refresh or a bookmark keeps it
  let profile = "default";
  try { profile = new URLSearchParams(location.search).get("profile") || "default"; } catch (e) { /* ignore */ }
  function syncUrl() {
    try {
      const u = new URL(location.href);
      if (profile === "default") u.searchParams.delete("profile"); else u.searchParams.set("profile", profile);
      history.replaceState(null, "", u.pathname + u.search + u.hash);
    } catch (e) { /* ignore */ }
  }
  let profileNames = ["default"];
  let loadedServer = "{}";
  const needsRestart = () => JSON.stringify(cfg.server || {}) !== loadedServer;
  let sample = null;
  // every place that loads a sample goes through here, so open condition editors can refresh their counts and suggestions
  function setSample(v) { sample = v; document.dispatchEvent(new Event("xsf-sample")); }
  let tab = "start";
  let previewTimer = null;
  let lastPreview = null;
  let lastSubid = "";
  const root = document.getElementById("app");

  async function api(path, body) {
    const opt = { method: body === undefined ? "GET" : "POST", headers: { "X-CSRF-Token": csrf, "X-Profile": profile }, credentials: "same-origin" };
    if (body !== undefined) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
    let r;
    try { r = await fetch(BASE + "/api/" + path, opt); } catch (e) { return { status: 0, ok: false, data: {} }; }
    let data = {};
    try { data = await r.json(); } catch (e) { /* not json */ }
    return { status: r.status, ok: r.ok, data };
  }

  // ---------- bound inputs ----------
  function setOrDelete(obj, key, val, empty) {
    if (empty) delete obj[key]; else obj[key] = val;
    changed();
  }
  function bindText(obj, key, opts = {}) {
    const i = h("input", { type: opts.num ? "number" : "text", value: obj[key] ?? "", placeholder: opts.placeholder || "",
      list: opts.list || null, step: opts.num ? "any" : null,
      oninput: () => {
        const v = i.value;
        setOrDelete(obj, key, opts.num ? Number(v) : v, v === "" && opts.optional !== false);
      } });
    return i;
  }
  function bindBool(obj, key, def) {
    const c = h("input", { type: "checkbox", checked: obj[key] ?? def,
      onchange: () => setOrDelete(obj, key, c.checked, c.checked === def) });
    return c;
  }
  function bindSelect(obj, key, options) {
    const s = h("select", { value: obj[key] ?? "", onchange: () => setOrDelete(obj, key, s.value, s.value === "") },
      options.map(([v, label]) => h("option", { value: v }, label)));
    s.value = obj[key] ?? "";
    return s;
  }
  function bindJSON(obj, key, rows = 4) {
    const ta = h("textarea", { rows, spellcheck: "false" });
    ta.value = obj[key] === undefined ? "" : JSON.stringify(obj[key], null, 2);
    ta.addEventListener("input", () => {
      const txt = ta.value.trim();
      if (txt === "") { ta.classList.remove("bad"); delete obj[key]; changed(); return; }
      try { obj[key] = JSON.parse(txt); ta.classList.remove("bad"); changed(); } catch (e) { ta.classList.add("bad"); }
    });
    return ta;
  }
  function field(label, input, hint, wide) {
    return h("label", { class: "f" + (wide ? " wide" : "") }, label, input, hint ? h("span", { class: "hint" }, hint) : null);
  }

  // ---------- conditions (`when`) ----------
  // `all` is accepted in rows mode only as a flat list of simple tests: that is where a second test on the same field is kept
  const allIsFlat = (v) => Array.isArray(v) && v.length > 0 && v.every((x) => x && typeof x === "object" && !Array.isArray(x) && !("all" in x) && isSimple(x));
  function isSimple(w) {
    if (w === undefined || w === null) return true;
    if (typeof w !== "object" || Array.isArray(w)) return false;
    for (const [k, v] of Object.entries(w)) {
      if (k === "all") { if (!allIsFlat(v)) return false; continue; }
      if (k.startsWith("_") || COMBINATORS.includes(k)) return false;
      if (v !== null && typeof v === "object") {
        if (Array.isArray(v)) return false;
        for (const [op, arg] of Object.entries(v)) {
          if (!OPS.includes(op)) return false;
          if (typeof arg === "object" && !(Array.isArray(arg) && (op === "in" || op === "not_in"))) return false;
        }
      }
    }
    return true;
  }
  // A row is "plain" (field + kind such as "ends with" + one or more words) or "advanced" (the raw operator and text).
  // Plain rows are written out as ordinary operators or a pattern when saved, so nothing new is stored in config.json,
  // and a pattern that only spells out words (like (AT|DT)$) is shown as plain words again when it is loaded.
  const PLAIN_KINDS = ["contains", "not_contains", "startswith", "endswith", "equals", "not_equals"];
  const POSITIVE_KINDS = ["contains", "startswith", "endswith", "equals"];
  const SUGGEST_FIELDS = ["protocol", "security", "network", "flag", "port", "sni", "host"];
  const RX_META = ".^$*+?{}[]()|\\";
  const escapeRx = (s) => String(s).replace(/[.^$*+?{}[\]()|\\]/g, "\\$&");
  // the words a pattern body spells out (a|b|c), or null when it uses any pattern feature
  function plainWords(src) {
    const words = [];
    let cur = "";
    for (let i = 0; i < src.length; i++) {
      const ch = src[i];
      if (ch === "\\") {
        const nx = src[i + 1];
        if (nx === undefined || !RX_META.includes(nx)) return null;
        cur += nx; i++;
      } else if (ch === "|") { words.push(cur); cur = ""; }
      else if (RX_META.includes(ch)) return null;
      else cur += ch;
    }
    words.push(cur);
    return words.every((x) => x !== "") ? words : null;
  }
  function parsePlainRegex(rx, ci) {
    let s = String(rx);
    const start = s.startsWith("^");
    if (start) s = s.slice(1);
    let end = false;
    if (s.endsWith("$")) {
      let n = 0;
      for (let i = s.length - 2; i >= 0 && s[i] === "\\"; i--) n++;
      if (n % 2 === 0) { end = true; s = s.slice(0, -1); }
    }
    let grouped = false;
    if (s.startsWith("(") && s.endsWith(")")) {
      s = s.slice(1, -1);
      if (s.startsWith("?:")) s = s.slice(2);
      grouped = true;
    }
    const words = plainWords(s);
    if (!words) return null;
    if (words.length > 1 && !grouped && (start || end)) return null;      // a|b$ does not mean (a|b)$
    return { op: start && end ? "equals" : start ? "startswith" : end ? "endswith" : "contains", words, ci: !!ci };
  }
  const isWordValue = (x) => typeof x === "string" || typeof x === "number";
  function toRow(f, op, arg) {
    const scalar = isWordValue(arg);
    if (scalar && ["contains", "startswith", "endswith", "equals"].includes(op)) return { f, plain: true, op, words: arg === "" ? [] : [String(arg)], ci: false };
    if (scalar && op === "icontains") return { f, plain: true, op: "contains", words: arg === "" ? [] : [String(arg)], ci: true };
    if (scalar && (op === "not_contains" || op === "not_equals")) return { f, plain: true, op, v: String(arg) };
    if (op === "in" && Array.isArray(arg) && arg.length && arg.every((x) => isWordValue(x) && String(x) !== "")) return { f, plain: true, op: "equals", words: arg.map(String), ci: false };
    if ((op === "regex" || op === "iregex") && typeof arg === "string") {
      const p = parsePlainRegex(arg, op === "iregex");
      if (p) return Object.assign({ f, plain: true }, p);
    }
    return { f, plain: false, op, v: Array.isArray(arg) ? arg.join(", ") : String(arg) };
  }
  function toRows(w) {
    const rows = [];
    for (const [f, v] of Object.entries(w || {})) {
      if (f === "all") { for (const part of v) rows.push(...toRows(part)); continue; }
      if (v !== null && typeof v === "object") for (const [op, arg] of Object.entries(v)) rows.push(toRow(f, op, arg));
      else rows.push(toRow(f, "equals", v));
    }
    return rows;
  }
  // the operator and argument a row is saved as; null while a plain row has no words yet
  function storeOf(r) {
    if (!r.plain) {
      let val = r.v;
      if (r.op === "in" || r.op === "not_in") val = r.v.split(",").map((x) => x.trim()).filter(Boolean);
      else if (r.op === "exists") val = r.v !== "false";
      else if (["gt", "gte", "lt", "lte"].includes(r.op)) val = r.v === "" || isNaN(Number(r.v)) ? 0 : Number(r.v);
      return { op: r.op, arg: val };
    }
    if (!POSITIVE_KINDS.includes(r.op)) return { op: r.op, arg: r.v ?? "" };
    const words = (r.words || []).filter((x) => x !== "");
    if (!words.length) return null;
    const one = words.length === 1;
    const group = one ? escapeRx(words[0]) : "(" + words.map(escapeRx).join("|") + ")";
    if (r.op === "equals") {
      if (!r.ci) return one ? { op: "equals", arg: words[0] } : { op: "in", arg: words };
      return { op: "iregex", arg: "^" + group + "$" };
    }
    if (r.op === "contains") {
      if (!r.ci) return one ? { op: "contains", arg: words[0] } : { op: "regex", arg: group };
      return one ? { op: "icontains", arg: words[0] } : { op: "iregex", arg: group };
    }
    if (!r.ci && one) return { op: r.op, arg: words[0] };
    return { op: r.ci ? "iregex" : "regex", arg: r.op === "startswith" ? "^" + group : group + "$" };
  }
  function fromRows(rows) {
    const w = {};
    const extra = [];
    for (const r of rows) {
      if (!r.f) continue;
      const s = storeOf(r);
      if (!s) continue;
      if (w[r.f] && s.op in w[r.f]) extra.push({ [r.f]: { [s.op]: s.arg } });      // the same test twice on one field: keep both
      else (w[r.f] = w[r.f] || {})[s.op] = s.arg;
    }
    const flat = (o) => { for (const f of Object.keys(o)) { const ops = Object.keys(o[f]); if (ops.length === 1 && ops[0] === "equals") o[f] = o[f].equals; } return o; };
    flat(w);
    if (extra.length) w.all = extra.map(flat);
    return w;
  }
  function fieldPicker(r, sync, render) {
    const custom = r.f && !FIELDS.includes(r.f);
    const sel = h("select", { onchange: (ev) => {
      if (ev.target.value === "__custom") { r.f = ""; sync(); render(); } else { r.f = ev.target.value; sync(); render(); }
    } }, FIELDS.map((f) => h("option", { value: f }, fieldLabel(f))), h("option", { value: "__custom" }, t("fieldCustom")));
    sel.value = custom || r.f === "" ? "__custom" : r.f;
    if (sel.value !== "__custom") return sel;
    return h("div", { class: "fpick" }, sel, h("input", { type: "text", value: r.f, placeholder: "streamSettings.network", oninput: (ev) => { r.f = ev.target.value; sync(); } }));
  }
  function describeWhen(w) {
    if (w && typeof w === "object" && !Array.isArray(w)) {
      const keys = Object.keys(w).filter((k) => !k.startsWith("_"));
      if (keys.length === 1 && (keys[0] === "all" || keys[0] === "any") && Array.isArray(w[keys[0]]) && w[keys[0]].length) {
        const parts = w[keys[0]].map((x) => describeWhen(x)).map((p) => (/\s/.test(p) && w[keys[0]].length > 1 ? "(" + p + ")" : p));
        return parts.join(" " + t(keys[0] === "all" ? "andWord" : "orWord") + " ");
      }
      if (keys.length === 1 && keys[0] === "not") return t("notWord") + " (" + describeWhen(w.not) + ")";
    }
    if (!isSimple(w)) return "{…}";
    const rows = toRows(w);
    if (!rows.length) return t("everyConfig");
    return rows.map(rowText).join(" " + t("andWord") + " ");
  }
  function rowText(r) {
    if (!r.plain) return fieldLabel(r.f) + " " + opLabel(r.op) + (r.op === "exists" ? "" : " \"" + r.v + "\"");
    const vals = (POSITIVE_KINDS.includes(r.op) ? r.words : [r.v]).map((x) => "\"" + x + "\"").join(" " + t("orWord") + " ");
    return fieldLabel(r.f) + " " + opLabel(r.op) + " " + (vals || "…") + (r.ci ? " (" + t("ciShort") + ")" : "");
  }
  // the real values (protocols, security, ...) seen in the loaded sample, fetched once per sample
  let factValues = null, factFor = null, factPromise = null;
  function sampleValues() {
    if (!sample) return Promise.resolve(null);
    if (factFor === sample && factValues) return Promise.resolve(factValues);
    const mine = sample;
    if (!factPromise || factPromise.sampleRef !== mine) {
      factPromise = api("facts", { configs: mine, whens: [] }).then((r) => {
        if (r.ok && sample === mine) { factValues = r.data.values; factFor = mine; }
        return factFor === sample ? factValues : null;
      });
      factPromise.sampleRef = mine;
    }
    return factPromise;
  }
  const knownValues = () => (factFor === sample ? factValues : null);

  function whenEditor(obj, key = "when", label = "when") {
    const box = h("div", { class: "when" });
    let mode = isSimple(obj[key]) ? "rows" : "json";
    const countEl = h("p", { class: "hint cond-count" });
    let countTimer = null, countSeq = 0;
    // "matches N of M configs in your sample", asked of the server so it uses exactly the engine's own matching
    function showCount() {
      clearTimeout(countTimer);
      countEl.textContent = "";
      if (mode !== "rows") return;
      countTimer = setTimeout(async () => {
        if (!box.isConnected) return;
        if (!sample) { countEl.textContent = t("condNoSample"); return; }
        const seq = ++countSeq;
        const r = await api("facts", { configs: sample, whens: [obj[key] || {}] });
        if (seq !== countSeq) return;
        const n = r.ok ? r.data.counts[0] : null;
        countEl.textContent = n === null || n === undefined ? t("condInvalid") : t("condMatches", { n: String(n), m: String(r.data.total) });
      }, 350);
    }
    const onSample = () => {
      if (!box.isConnected) { document.removeEventListener("xsf-sample", onSample); return; }
      draw();
    };
    document.addEventListener("xsf-sample", onSample);
    function draw() {
      box.replaceChildren();
      const head = h("div", { class: "row" }, h("h4", {}, t(label)));
      const toggle = h("button", { type: "button", onclick: () => {
        if (mode === "rows") { mode = "json"; draw(); } else if (isSimple(obj[key])) { mode = "rows"; draw(); } else alert(t("notSimple"));
      } }, mode === "rows" ? t("jsonMode") : t("rowsMode"));
      head.append(toggle);
      box.append(head);
      if (mode === "json") {
        box.append(bindJSON(obj, key, 4));
        showCount();
        return;
      }
      const rows = toRows(obj[key]);
      const sync = () => { const w = fromRows(rows); if (Object.keys(w).length) obj[key] = w; else delete obj[key]; changed(); showCount(); };
      const list = h("div");

      // the old look: any operator, one text box
      const advancedRow = (r, idx) => {
        const val = r.op === "exists"
          ? h("select", { onchange: (ev) => { r.v = ev.target.value; sync(); } }, h("option", { value: "true" }, "true"), h("option", { value: "false" }, "false"))
          : h("input", { type: "text", value: r.v, placeholder: t("value"), oninput: (ev) => { r.v = ev.target.value; sync(); } });
        if (r.op === "exists") val.value = r.v === "false" ? "false" : "true";
        const opSel = h("select", { onchange: (ev) => { r.op = ev.target.value; if (r.op === "exists") r.v = "true"; sync(); render(); } },
          OPS.map((o) => h("option", { value: o }, opLabel(o))));
        opSel.value = r.op;
        const s0 = storeOf(r);
        const simple = s0 ? toRow(r.f, s0.op, s0.arg) : null;
        const back = simple && simple.plain
          ? h("button", { type: "button", class: "linklike", onclick: () => { rows[idx] = simple; sync(); render(); } }, t("rowSimple"))
          : h("span", { class: "hint" }, t("notPlain"));
        return h("div", { class: "cond-wrap" },
          h("div", { class: "cond" }, fieldPicker(r, sync, render), opSel, val,
            h("button", { type: "button", class: "danger", "aria-label": t("remove"), onclick: () => { rows.splice(idx, 1); sync(); render(); } }, "×")),
          h("div", { class: "row" }, back));
      };

      // the new look: field, kind, words (any one of them is enough)
      const plainRow = (r, idx) => {
        const positive = POSITIVE_KINDS.includes(r.op);
        const kindSel = h("select", { onchange: (ev) => {
          const kind = ev.target.value;
          if (kind === "__adv") {
            const s = storeOf(r) || { op: r.op, arg: "" };
            rows[idx] = { f: r.f, plain: false, op: s.op, v: Array.isArray(s.arg) ? s.arg.join(", ") : String(s.arg) };
            render();
            return;
          }
          const toPositive = POSITIVE_KINDS.includes(kind);
          if (toPositive && !positive) { r.words = r.v ? [r.v] : []; r.ci = false; delete r.v; }
          else if (!toPositive && positive) { r.v = (r.words || [])[0] || ""; delete r.words; delete r.ci; }
          r.op = kind;
          sync(); render();
        } }, PLAIN_KINDS.map((k) => h("option", { value: k }, opLabel(k))), h("option", { value: "__adv" }, t("rowAdvanced")));
        kindSel.value = r.op;

        const sug = h("div", { class: "suggest" });
        const drawSuggest = (vals) => {
          const found = vals && SUGGEST_FIELDS.includes(r.f) && positive ? vals[r.f] : null;
          if (!found || !found.length) { sug.replaceChildren(); return; }
          sug.replaceChildren(h("span", { class: "hint" }, t("suggestFrom")), ...found.slice(0, 12).map(([val, n]) =>
            h("button", { type: "button", class: "pill" + (r.words.includes(val) ? " on" : ""), onclick: () => {
              const i = r.words.indexOf(val);
              if (i >= 0) r.words.splice(i, 1); else r.words.push(val);
              sync(); render();
            } }, val + " (" + n + ")")));
        };
        if (positive) sampleValues().then((vals) => { if (box.isConnected) drawSuggest(vals); });

        let valueEl, extra = null;
        if (positive) {
          valueEl = chipsInput(r.words, () => { sync(); drawSuggest(knownValues()); }, t("addWordPh"));
          extra = h("label", { class: "check small" },
            h("input", { type: "checkbox", checked: !!r.ci, onchange: (ev) => { r.ci = ev.target.checked; sync(); } }), t("ciLabel"));
        } else {
          valueEl = h("input", { type: "text", value: r.v ?? "", placeholder: t("value"), oninput: (ev) => { r.v = ev.target.value; sync(); } });
        }
        return h("div", { class: "cond-wrap" },
          h("div", { class: "cond plain" }, fieldPicker(r, sync, render), kindSel,
            h("button", { type: "button", class: "danger", "aria-label": t("remove"), onclick: () => { rows.splice(idx, 1); sync(); render(); } }, "×"),
            valueEl),
          sug, extra);
      };

      const render = () => {
        list.replaceChildren(...rows.map((r, idx) => (r.plain ? plainRow(r, idx) : advancedRow(r, idx))));
      };
      render();
      box.append(list, h("div", { class: "row" },
        h("button", { type: "button", onclick: () => { rows.push({ f: "remark", plain: true, op: "contains", words: [], ci: false }); render(); } }, t("addCond")),
        h("span", { class: "hint" }, t("whenHint"))), countEl);
      showCount();
    }
    draw();
    return box;
  }

  // ---------- item lists ----------
  const OPEN_ITEMS = new WeakSet();          // items shown expanded (all start collapsed)
  const OPEN_SECT = new Set();               // titles of <details> sections the user opened
  function detailsBox(titleKey, child, openByDefault) {
    const d = h("details", { class: "sect" }, h("summary", {}, t(titleKey)), child);
    d.open = OPEN_SECT.has(titleKey) || (openByDefault && !OPEN_SECT.has("-" + titleKey));
    d.addEventListener("toggle", () => { if (d.open) { OPEN_SECT.add(titleKey); OPEN_SECT.delete("-" + titleKey); } else { OPEN_SECT.delete(titleKey); OPEN_SECT.add("-" + titleKey); } });
    return d;
  }
  const moreBox = (...kids) => h("details", { class: "more" }, h("summary", {}, t("moreOptions")), ...kids);
  function listEditor(kind, hintKey, newItem, body, templates) {
    const wrap = h("div");
    const items = (cfg[kind] = cfg[kind] || []);
    function draw() {
      wrap.replaceChildren(h("p", { class: "hint" }, t(hintKey)));
      items.forEach((it, idx) => {
        const open = OPEN_ITEMS.has(it);
        const toggle = () => { if (OPEN_ITEMS.has(it)) OPEN_ITEMS.delete(it); else OPEN_ITEMS.add(it); draw(); };
        const move = (d) => { const j = idx + d; if (j < 0 || j >= items.length) return; [items[idx], items[j]] = [items[j], items[idx]]; changed(); draw(); };
        wrap.append(h("div", { class: "item" + (open ? " open" : "") + (it.enabled === false ? " off" : "") },
          h("div", { class: "item-head" },
            h("button", { type: "button", class: "twisty", "aria-expanded": String(open), title: open ? "−" : "+", onclick: toggle }, open ? "▾" : "▸"),
            h("strong", { class: "item-title", onclick: toggle }, prettyId(it.id) || t("unnamed")),
            h("label", { class: "check" }, bindBool(it, "enabled", true), t("enabled")),
            h("button", { type: "button", onclick: () => move(-1), "aria-label": "↑" }, "↑"),
            h("button", { type: "button", onclick: () => move(1), "aria-label": "↓" }, "↓"),
            open ? h("button", { type: "button", class: "danger", onclick: () => { if (confirm(t("confirmDel"))) { items.splice(idx, 1); changed(); draw(); } } }, t("remove")) : null),
          h("div", { onclick: open ? null : toggle, class: open ? "" : "clickable" }, summaryLine(kind, it)),
          open ? h("details", { class: "more" }, h("summary", {}, t("renameItem")),
            field(t("id"), h("input", { type: "text", value: it.id ?? "", oninput: (e) => { it.id = e.target.value; changed(); } }), t("renameHint"))) : null,
          open ? body(it) : null));
      });
      const addItem = (made) => { items.push(made); OPEN_ITEMS.add(made); changed(); draw(); };
      if (templates && templates.length) {
        const sel = h("select", { class: "add-from", onchange: () => {
          const tpl = templates[Number(sel.value)];
          sel.value = "";
          if (tpl) addItem(tpl[1](items));
        } }, h("option", { value: "" }, t("addFrom")), templates.map(([label], i) => h("option", { value: String(i) }, t(label))));
        wrap.append(sel);
      } else {
        wrap.append(h("button", { type: "button", onclick: () => addItem(newItem(items)) }, t("add")));
      }
    }
    draw();
    return wrap;
  }
  function summaryLine(kind, it) {
    let txt = "";
    if (kind === "rules") txt = t("whenIf") + " " + describeWhen(it.when) + " → " + t(it.do || "keep");
    else if (kind === "groups") txt = t(it.split_by && it.split_by.regex ? "sum_group_split" : "sum_group", { when: describeWhen(it.when), name: it.name || prettyId(it.id) });
    else if (kind === "chains") txt = t(it.mode === "exit_first" ? "sum_chain_exit" : "sum_chain_entry", { when: describeWhen(it.exit_when) });
    else if (kind === "order") txt = describeWhen(it.when) + " → " + t("rank") + " " + (it.rank ?? 0);
    else txt = describeWhen(it.when);
    return h("p", { class: "summary" }, txt);
  }
  // the technical name is kept as stored; people see it as words: "drop-tunnel-singles" -> "Drop tunnel singles"
  function prettyId(id) {
    const s = String(id ?? "").trim();
    if (!/[-_]/.test(s)) return s;
    const w = s.replace(/[-_]+/g, " ").trim();
    return w.charAt(0).toUpperCase() + w.slice(1);
  }
  const nextId = (prefix, items) => { let n = items.length + 1; while (items.some((x) => x.id === prefix + n)) n++; return prefix + n; };

  const ruleBody = (r) => h("div", {}, whenEditor(r),
    h("div", { class: "row" }, field(t("do"), bindSelect(r, "do", [["keep", t("keep")], ["drop", t("drop")], ["pin_top", t("pin_top")], ["pin_bottom", t("pin_bottom")]]))));

  // ---------- "one balancer / chain for each ..." ----------
  // Stored as split_by {field, regex}: each choice below writes the usual pattern, so nothing new is saved, and a
  // split_by written by hand that matches a choice is shown as that choice when it is loaded.
  const SPLIT_FIELDS = ["protocol", "network", "security", "sni", "host", "port", "address"];
  const SPLIT_WORD = "^([^ _-]+)";
  const escClass = (c) => (/[\]\\^]/.test(c) ? "\\" + c : c);
  function parseAfter(rx) {                       // ^TEXT([^X]+)  or  ^TEXT(.+)
    const m = /^\^(.*)\((?:\[\^(\\.|[^\]\\])\]\+|\.\+)\)$/s.exec(rx);
    if (!m) return null;
    const w = plainWords(m[1]);
    if (!w || w.length !== 1) return null;
    if (m[2] && m[2].length === 2 && !(RX_META + "-]").includes(m[2][1])) return null;      // [^\d] is not a character
    return { prefix: w[0], until: m[2] === undefined ? "" : m[2].length === 2 ? m[2][1] : m[2] };
  }
  function splitFromStored(sb) {
    const s = { mode: "none", field: "protocol", prefix: "", until: "", rfield: "remark", regex: "" };
    if (!sb || typeof sb !== "object" || !sb.regex) return s;
    const f = sb.field || "remark";
    if (sb.regex === "(.+)" && f === "flag") s.mode = "flag";
    else if (sb.regex === "(.+)" && SPLIT_FIELDS.includes(f)) { s.mode = "field"; s.field = f; }
    else if (f === "remark" && sb.regex === SPLIT_WORD) s.mode = "word";
    else {
      const a = f === "remark" ? parseAfter(sb.regex) : null;
      if (a) Object.assign(s, a, { mode: "after" });
      else Object.assign(s, { mode: "regex", rfield: f, regex: sb.regex });
    }
    return s;
  }
  function splitToStored(s) {
    if (s.mode === "flag") return { field: "flag", regex: "(.+)" };
    if (s.mode === "field") return { field: s.field, regex: "(.+)" };
    if (s.mode === "word") return { field: "remark", regex: SPLIT_WORD };
    if (s.mode === "after") return { field: "remark", regex: "^" + escapeRx(s.prefix) + (s.until ? "([^" + escClass(s.until) + "]+)" : "(.+)") };
    if (s.mode === "regex" && s.regex) return { field: s.rfield || "remark", regex: s.regex };
    return null;
  }
  function splitEditor(item, kind) {
    const box = h("div", { class: "split" });
    const s = splitFromStored(item.split_by);
    const chain = kind === "chains";
    const apply = () => { const v = splitToStored(s); if (v) item.split_by = v; else delete item.split_by; changed(); };
    function draw() {
      const sel = h("select", { onchange: (e) => {
        const prev = splitToStored(s);
        s.mode = e.target.value;
        if (s.mode === "regex" && prev) { s.rfield = prev.field; s.regex = prev.regex; }      // start from what was chosen before
        apply(); draw();
      } }, ["none", "flag", "field", "word", "after", "regex"].map((m) =>
        h("option", { value: m }, t(m === "none" ? (chain ? "sp_none_chain" : "sp_none_group") : "sp_" + m))));
      sel.value = s.mode;
      const extra = [];
      if (s.mode === "field") {
        const fsel = h("select", { onchange: (e) => { s.field = e.target.value; apply(); } }, SPLIT_FIELDS.map((f) => h("option", { value: f }, fieldLabel(f))));
        fsel.value = s.field;
        extra.push(field(t("sp_fieldPick"), fsel));
      } else if (s.mode === "after") {
        extra.push(h("div", { class: "grid" },
          field(t("sp_afterText"), h("input", { type: "text", value: s.prefix, oninput: (e) => { s.prefix = e.target.value; apply(); } }), t("sp_afterHint")),
          field(t("sp_untilChar"), h("input", { type: "text", value: s.until, maxlength: "1", oninput: (e) => { s.until = e.target.value; apply(); } }), t("sp_untilHint"))));
      } else if (s.mode === "regex") {
        extra.push(h("div", { class: "grid" },
          field(t("splitField"), h("input", { type: "text", list: "dl-fields", value: s.rfield, oninput: (e) => { s.rfield = e.target.value; apply(); } })),
          field(t("splitRegex"), h("input", { type: "text", value: s.regex, oninput: (e) => { s.regex = e.target.value; apply(); } }), t(chain ? "hint_chain_split" : "hint_split"))));
      }
      box.replaceChildren(field(t(chain ? "sp_title_chain" : "sp_title_group"), sel, null, true), ...extra);
    }
    draw();
    return box;
  }

  const groupBody = (g) => {
    return h("div", {}, whenEditor(g), splitEditor(g, "groups"),
      h("div", { class: "grid" },
        field(t("name"), bindText(g, "name")),
        field(t("type"), bindText(g, "type", { list: "dl-types", optional: false }))),
      moreBox(
        h("div", { class: "grid" },
          field(t("probeKind"), bindSelect(g, "probe_kind", [["", t("auto")], ["burst", "burst"], ["observatory", "observatory"]])),
          field(t("minMembers"), bindText(g, "min_members", { num: true })),
          field(t("position"), bindSelect(g, "position", [["", t("default")], ["top", t("top")], ["bottom", t("bottom")]]))),
        h("div", { class: "row" }, h("label", { class: "check" }, bindBool(g, "remove_members_from_output", true), t("removeMembers"))),
        field(t("params"), bindJSON(g, "params"), null, true),
        field(t("probe"), bindJSON(g, "probe"), null, true),
        field(t("memberCost"), bindJSON(g, "member_cost"), null, true),
        expandEditor(g),
        h("div", { class: "row" }, h("label", { class: "check" }, bindBool(g, "include_balanced", false), t("includeBalanced"))),
        field(t("memberPosition"), bindJSON(g, "member_position"), t("memberPositionHint"), true),
        field(t("catchall"), bindJSON(g, "catchall_rules"), t("catchallHint"), true),
        memberPatchEditor(g)));
  };

  const chainBody = (c) => {
    const modeBox = h("div");
    const drawMode = () => {
      const exitFirst = c.mode === "exit_first";
      if (exitFirst) {
        modeBox.replaceChildren(
          h("div", { class: "row" }, h("label", { class: "check" }, bindBool(c, "remove_exit_from_output", false), t("removeExit"))),
          field(t("entry"), bindJSON(c, "entry", 4), t("entryHint"), true),
          h("div", { class: "grid" },
            field(t("chainEndpoints"), bindText(c, "endpoints"), t("chainEndpointsHint")),
            field(t("chainPick"), bindSelect(c, "pick", [["", t("pickRandom")], ["random", t("pickRandom")], ["per_user", t("pickUser")]]))),
          field(t("chainExit"), bindJSON(c, "exit", 4), t("chainExitHint"), true),
          field(t("chainEntryMerge"), bindJSON(c, "entry_merge", 8), t("chainEntryMergeHint"), true),
          field(t("chainBefore"), bindJSON(c, "before", 6), t("chainBeforeHint"), true));
      } else {
        modeBox.replaceChildren(
          h("div", { class: "row" },
            h("label", { class: "check" }, bindBool(c, "through_exit", true), t("throughExit")),
            h("label", { class: "check" }, bindBool(c, "remove_exit_from_output", false), t("removeExit"))),
          field(t("entry"), bindJSON(c, "entry", 10), t("entryHint"), true),
          field(t("choices"), bindJSON(c, "choices", 4), t("choicesHint"), true));
      }
    };
    const modeSel = h("select", { onchange: () => { if (modeSel.value === "exit_first") c.mode = "exit_first"; else delete c.mode; changed(); drawMode(); } },
      h("option", { value: "entry_first" }, t("modeEntry")), h("option", { value: "exit_first" }, t("modeExit")));
    modeSel.value = c.mode === "exit_first" ? "exit_first" : "entry_first";
    drawMode();
    return h("div", {}, whenEditor(c, "exit_when", "exitWhen"),
      field(t("chainMode"), modeSel, null, true), splitEditor(c, "chains"),
      h("div", { class: "grid" }, field(t("name"), bindText(c, "name"))),
      moreBox(field(t("position"), bindSelect(c, "position", [["", t("default")], ["top", t("top")], ["bottom", t("bottom")]])), modeBox));
  };

  const patchBody = (p) => h("div", {}, whenEditor(p),
    h("div", { class: "grid" },
      field(t("stage"), bindSelect(p, "stage", [["", t("source")], ["output", t("output")]])),
      field(t("target"), bindSelect(p, "target", [["", t("config")], ["outbound", t("outbound")]]))),
    field(t("merge"), bindJSON(p, "merge", 6), null, true),
    field(t("routingPre"), bindJSON(p, "routing_prepend"), null, true),
    field(t("routingPost"), bindJSON(p, "routing_append"), null, true));

  function registerEditor(a, extraMore = []) {
    const r = (a.register = a.register || {});
    const subid = h("input", { type: "text", placeholder: "" });
    const msg = h("span", { class: "hint" });
    const btn = h("button", { type: "button", onclick: async () => {
      if (isDirty()) { msg.textContent = t("regSaveFirst"); return; }
      btn.disabled = true; msg.textContent = "…";
      const res = await api("register-account", { subid: subid.value.trim() });
      btn.disabled = false;
      msg.textContent = res.ok ? (res.data.created ? t("regOk") : t("regExists")) : (res.data.error || "error");
    } }, t("regNow"));
    return h("div", {},
      h("label", { class: "check" }, bindBool(r, "enabled", false), t("regEnabled")),
      field(t("regSubid"), subid),
      h("div", {}, btn, " ", msg),
      moreBox(...extraMore, h("div", { class: "grid" },
        field(t("regRetry"), bindText(r, "retry_seconds", { num: true, placeholder: "600" })),
        field(t("regApi"), bindText(r, "api")),
        field(t("regVersion"), bindText(r, "client_version")))));
  }

  async function restartService() {
    if (!confirm(t("restartConfirm"))) return;
    setStatus(t("restarting"), "dirty");
    const r = await api("restart", {});
    if (!r.ok) { setStatus(t("restartFail", { err: r.data.error || "error" }), "err"); return; }
    for (let i = 0; i < 40; i++) {
      await new Promise((res) => setTimeout(res, 1500));
      const me = await api("me");
      if (me.ok) { loadedServer = JSON.stringify(cfg.server || {}); updateRestartBtn(); setStatus(t("restarted"), "ok"); if (tab === "settings") drawEditor(); return; }
    }
    setStatus(t("restartFail", { err: "timeout" }), "err");
  }
  function restartBlock() {
    const box = h("div", { class: "restart" });
    box.append(h("p", { class: "hint" }, t("restartNote")));
    if (needsRestart()) box.append(h("div", { class: "msg warn" }, t("restartNeeded")));
    if (!canRestart) box.append(h("p", { class: "hint" }, t("restartManual")));
    return box;
  }

  // the mode choice and the pass-through formats; used by the wizard and by Settings
  function modeEditor(p, onMode) {
    const sel = h("select", { onchange: () => { if (sel.value === "proxy") { p.mode = "proxy"; delete p.source; delete p.raw_mode; } else delete p.mode; changed(); onMode(); } },
      h("option", { value: "" }, t("modeEngine")), h("option", { value: "proxy" }, t("modeProxy")));
    sel.value = p.mode === "proxy" ? "proxy" : "";
    return h("div", {}, field(t("modeTitle"), sel, p.mode === "proxy" ? t("modeProxyHelp") : null, true));
  }
  const formatFields = (p) => h("div", {},
    field(t("rawUrl"), bindText(p, "raw_url", { placeholder: "https://panel.example.com:2096/sub/" }), t("formatUrlHint"), true),
    field(t("clashUrl"), bindText(p, "clash_url", { placeholder: "https://panel.example.com:2096/clash/" }), null, true));

  // more domain names, each with its own certificate (picked by the name the app asks for)
  function domainsEditor(s) {
    const box = h("div", { class: "domains" });
    const draw = () => {
      const list = Array.isArray(s.domains) ? s.domains : [];
      const set = () => { if (list.length) s.domains = list; else delete s.domains; changed(); };
      box.replaceChildren(h("h3", {}, t("domainsTitle")), h("p", { class: "hint" }, t("domainsHint")),
        ...list.map((d, i) => {
          const inp = (key, ph) => h("input", { type: "text", value: d[key] || "", placeholder: ph, "aria-label": t("dom_" + key),
            oninput: (e) => { if (e.target.value) d[key] = e.target.value; else delete d[key]; set(); } });
          return h("div", { class: "domain-row" }, inp("name", "sub2.example.com"), inp("cert", "/path/fullchain.pem"), inp("key", "/path/privkey.pem"),
            h("button", { type: "button", class: "icon danger", "aria-label": t("remove"), onclick: () => { list.splice(i, 1); set(); draw(); } }, "×"));
        }),
        h("button", { type: "button", onclick: () => { list.push({ name: "" }); s.domains = list; draw(); } }, t("domainAdd")));
    };
    draw();
    return box;
  }

  function settingsEditor() {
    const s = (cfg.server = cfg.server || {});
    const p = (cfg.panel = cfg.panel || {});
    const a = (cfg.accounts = cfg.accounts || {});
    // three cards; what most people never change sits under "More options" in each
    return h("div", {},
      detailsBox("sectPanelConn", h("div", {},
        h("p", { class: "hint" }, t("panelConnHint")),
        modeEditor(p, () => drawEditor()),
        p.mode === "proxy" ? null : h("div", { class: "grid" },
          field(t("sourceLabel"), bindSelect(p, "source", [["", t("sourceJson")], ["raw", t("sourceRaw")]]), t("sourceHint")),
          field(t("rawModeLabel"), bindSelect(p, "raw_mode", [["", t("rawPass")], ["engine", t("rawEngine")]]), t("rawModeHint"))),
        p.source === "raw" ? h("div", { class: "msg warn" }, t("rawWarn")) : null,
        p.mode === "proxy" ? h("p", { class: "hint" }, t("proxyHelp")) : null,
        field(t(p.mode === "proxy" ? "jsonUrl" : "panelUrl"), bindText(p, "url", { placeholder: "https://panel.example.com:2096/json/" }), null, true),
        formatFields(p),
        h("label", { class: "check" }, bindBool(p, "verify_tls", true), t("verifyTls")),
        moreBox(
          h("div", { class: "grid" },
            field(t("pageUrl"), bindText(p, "page_url"), null, true),
            field(t("timeout"), bindText(p, "timeout", { num: true, placeholder: "10" }))),
          field(t("headers"), bindJSON(p, "headers"), null, true),
          field(t("passHeaders"), bindJSON(p, "pass_headers"), null, true),
          field(t("jsonTemplate"), bindJSON(p, "json_template", 8), t("jsonTemplateHint"), true))), true),
      detailsBox("sectSubServer", h("div", {},
        h("div", { class: "grid" },
          field(t("host"), bindText(s, "host", { placeholder: "127.0.0.1" })),
          field(t("port"), bindText(s, "port", { num: true, placeholder: "8080" })),
          field(t("route"), bindText(s, "route", { placeholder: "/sub/" })),
          field(t("rawRoute"), bindText(s, "raw_route", { placeholder: "/raw/" })),
          field(t("clashRoute"), bindText(s, "clash_route", { placeholder: "/clash/" }))),
        h("h3", {}, t("httpsTitle")),
        h("p", { class: "hint" }, t("httpsHint")),
        h("div", { class: "grid" },
          field(t("tlsCert"), bindText(s, "tls_cert", { placeholder: "/etc/xraysubforge/certs/fullchain.pem" })),
          field(t("tlsKey"), bindText(s, "tls_key", { placeholder: "/etc/xraysubforge/certs/privkey.pem" }))),
        domainsEditor(s),
        moreBox(h("div", { class: "grid" },
          field(t("subidRegex"), bindText(s, "subid_regex")),
          field(t("workers"), bindText(s, "workers", { num: true })),
          field(t("threads"), bindText(s, "threads", { num: true })))),
        restartBlock())),
      (cfg.panel || {}).mode === "proxy" ? null : detailsBox("sectAccountsWarp", registerEditor(a, [
        field(t("accountFile"), bindText(a, "file", { placeholder: "accounts.json" }), t("accountHint"), true),
        field(t("accountDefault"), bindJSON(a, "default"), null, true)])));
  }

  function rawEditor() {
    const ta = h("textarea", { rows: 24, spellcheck: "false" });
    ta.value = JSON.stringify(cfg, null, 2);
    const msg = h("span", { class: "hint" });
    return h("div", {}, ta, h("div", { class: "row" },
      h("button", { type: "button", class: "primary", onclick: () => {
        try { const v = JSON.parse(ta.value); if (!v || typeof v !== "object" || Array.isArray(v)) throw new Error(); cfg = v; msg.textContent = ""; changed(); drawEditor(); }
        catch (e) { msg.textContent = t("jsonBad"); ta.classList.add("bad"); }
      } }, t("apply")), msg));
  }


  // ---------- setup wizard ----------
  const WARP_ENDPOINTS = ["162.159.198.114", "162.159.198.206", "162.159.198.186", "162.159.198.135", "162.159.198.219", "162.159.198.64", "162.159.198.231", "162.159.198.250", "162.159.198.184", "162.159.198.197", "162.159.198.48", "162.159.198.203", "162.159.198.230", "162.159.199.87", "162.159.199.127", "162.159.199.188", "162.159.199.163", "162.159.199.193", "162.159.199.102", "162.159.199.76", "162.159.199.192", "162.159.199.111", "162.159.199.113", "162.159.199.46", "162.159.199.109", "162.159.199.106", "162.159.199.101", "162.159.199.190", "162.159.199.235", "162.159.199.100", "162.159.199.83", "162.159.199.37", "162.159.199.149"];
  const WARP_ENTRY = {
  "protocol": "masque",
  "settings": {
    "address": "{choice.endpoint}",
    "port": 443
  },
  "targetStrategy": "UseIPv4v6",
  "streamSettings": {
    "sockopt": {
      "domainStrategy": "UseIP",
      "happyEyeballs": {
        "tryDelayMs": 250,
        "prioritizeIPv6": false,
        "interleave": 2,
        "maxConcurrentTry": 20
      }
    },
    "method": "masque",
    "security": "tls",
    "tlsSettings": {
      "serverName": "www.cloudflare.com",
      "fingerprint": "ios",
      "alpn": [
        "h2"
      ]
    },
    "masqueSettings": {
      "warp": {
        "privateKey": "{account.privateKey}",
        "publicKey": "{account.publicKey}",
        "address": "{account.address}"
      }
    }
  }
};
  const wiz = { step: 0, hide: { on: false, items: [] }, bal: { on: false, items: [], split: "", type: "leastLoad" },
    warp: { on: false, items: [], endpoints: WARP_ENDPOINTS.join("\n"), auto: true }, checks: null, running: false, done: false, connMsg: null };

  function upsert(kind, item) {
    const l = (cfg[kind] = cfg[kind] || []);
    const i = l.findIndex((x) => x.id === item.id);
    if (i >= 0) l[i] = item; else l.push(item);
  }
  function dropWiz(kind, id) { if (cfg[kind]) cfg[kind] = cfg[kind].filter((x) => x.id !== id); }
  const escapeRegex = (x) => x.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  // one text -> "contains"; several -> one case-insensitive pattern that matches any of them
  const nameCond = (items) => ({ remark: items.length === 1 ? { icontains: items[0] } : { iregex: items.map(escapeRegex).join("|") } });
  function bUpsert(blk) {
    if (!isObj(cfg.blocks) || !Array.isArray(cfg.blocks.list)) cfg.blocks = { rest: "keep", list: [] };
    const list = cfg.blocks.list, i = list.findIndex((x) => x.id === blk.id);
    if (i >= 0) list[i] = blk;
    else if (blk.type === "drop") list.push(blk);
    else { const firstOther = list.findIndex((x) => x.type !== "balancer"); if (firstOther < 0) list.push(blk); else list.splice(firstOther, 0, blk); }
  }
  function bDrop(id) { if (isObj(cfg.blocks) && Array.isArray(cfg.blocks.list)) cfg.blocks.list = cfg.blocks.list.filter((x) => x.id !== id); }
  function applyGoals() {
    const hide = wiz.hide.items, bal = wiz.bal.items;
    // the setup guide writes blocks (shown in the Blocks tab); WARP still uses a chain
    if (wiz.hide.on && hide.length) bUpsert({ id: "wiz-hide", name: t("goalHide"), type: "drop", kinds: [nameCond(hide)] }); else bDrop("wiz-hide");
    dropWiz("rules", "hide-configs");
    if (wiz.bal.on && bal.length) {
      const blk = { id: "wiz-balance", name: bal.join(" + "), type: "balancer", kinds: [nameCond(bal)], settings: { strategy: wiz.bal.type } };
      if (!["leastLoad", "leastPing", "random", "roundRobin"].includes(wiz.bal.type)) { delete blk.settings; }
      if (wiz.bal.split.trim()) blk.advanced = { group: { split_by: { field: "remark", regex: wiz.bal.split.trim() }, name: "{split}" } };
      bUpsert(blk);
    } else bDrop("wiz-balance");
    dropWiz("groups", "balance-configs");
    changed();
  }
  const matchCount = (items) => {
    if (!sample || !items.length) return null;
    const needles = items.map((x) => x.toLowerCase());
    return sample.filter((c) => { const r = String(c.remarks ?? "").toLowerCase(); return needles.some((n) => r.includes(n)); }).length;
  };
  // a box where each typed text becomes a chip (Enter or comma adds it, Backspace on an empty box removes the last one)
  function chipsInput(items, onChange, placeholder) {
    const wrap = h("div", { class: "chips-wrap" });
    const box = h("div", { class: "chips" });
    const input = h("input", { type: "text", placeholder, autocomplete: "off" });
    const SEP = /[,،;؛\n]/;                                  // Latin and Persian comma / semicolon, new line
    const add = (raw) => {
      raw.split(SEP).map((x) => x.trim()).filter(Boolean).forEach((x) => { if (!items.includes(x)) items.push(x); });
      input.value = ""; draw(); onChange(); input.focus();
    };
    function draw() {
      box.replaceChildren(...items.map((x, i) => h("span", { class: "chip big" }, x,
        h("button", { type: "button", "aria-label": "×", onclick: () => { items.splice(i, 1); draw(); onChange(); } }, "×"))), input);
    }
    // keydown covers Enter on all keyboards; the input event covers a typed or pasted separator whatever the layout / IME sends
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.keyCode === 13) { e.preventDefault(); if (input.value.trim() && !e.isComposing) add(input.value); }
      else if (e.key === "Backspace" && !input.value && items.length) { items.pop(); draw(); onChange(); input.focus(); }
    });
    input.addEventListener("input", (e) => { if (!e.isComposing && SEP.test(input.value)) add(input.value); });
    input.addEventListener("compositionend", () => { if (SEP.test(input.value)) add(input.value); });
    input.addEventListener("blur", () => { if (input.value.trim()) add(input.value); });
    draw();
    return h("div", { class: "chips-row" }, box,
      h("button", { type: "button", class: "chips-add", onclick: () => { if (input.value.trim()) add(input.value); else input.focus(); } }, t("addWord")));
  }

  function checkText(c) {
    const a = Object.assign({}, c.args || {});
    const kind = a.kind;
    for (const key of [kind ? "c_" + c.id + "_" + c.status + "_" + kind : null, "c_" + c.id + "_" + c.status]) {
      if (key && (STR[lang][key] || STR.en[key])) return t(key, a);
    }
    return c.text;
  }
  function checksView() {
    const box = h("div", { class: "checks" });
    if (wiz.running) { box.append(h("p", { class: "hint" }, t("running"))); return box; }
    (wiz.checks || []).forEach((c) => {
      const icon = { ok: "✓", warn: "!", fail: "✗", skip: "–" }[c.status] || "?";
      box.append(h("div", { class: "check-row " + c.status }, h("span", { class: "ci" }, icon), h("div", {}, checkText(c),
        c.args && c.args.problems ? h("ul", {}, c.args.problems.map((m) => h("li", {}, m))) : null)));
    });
    return box;
  }
  async function runChecks() {
    wiz.running = true; drawEditor();
    const r = await api("checks", { config: cfg, subid: lastSubid });
    wiz.running = false; wiz.checks = r.ok ? r.data.checks : [];
    drawEditor();
  }

  function wizardView() {
    const proxyMode = (cfg.panel || {}).mode === "proxy";
    if (proxyMode) wiz.step = 0;
    const names = proxyMode ? [t("step1")] : [t("step1"), t("step2"), t("step3"), t("step4")];
    const nav = h("div", { class: "steps" }, names.map((n, i) => h("button", { type: "button", class: "step" + (i === wiz.step ? " on" : i < wiz.step ? " past" : ""),
      onclick: () => goStep(i) }, h("b", {}, i + 1), " ", n)));
    const body = h("div", { class: "wiz" });
    const buttons = (nextLabel, onNext, canBack = true) => h("div", { class: "row" },
      canBack && wiz.step > 0 ? h("button", { type: "button", onclick: () => goStep(wiz.step - 1) }, t("back")) : null,
      h("button", { type: "button", class: "primary", onclick: onNext || (() => goStep(wiz.step + 1)) }, nextLabel || t("next")));

    if (wiz.done) {
      const route = ((cfg.server && cfg.server.route) || loadedRoute || "/sub/");
      const link = location.origin + route.replace(/\/?$/, "/") + "<id>";
      const extra = [];
      if (proxyMode) {
        for (const [urlKey, routeKey, def, label] of [["url", "route", "/sub/", "doneLinkJson"], ["raw_url", "raw_route", "/raw/", "doneLinkRaw"], ["clash_url", "clash_route", "/clash/", "doneLinkClash"]]) {
          const rt = (cfg.server && cfg.server[routeKey] !== undefined) ? cfg.server[routeKey] : (routeKey === "route" ? route : def);
          if ((cfg.panel || {})[urlKey] && rt) extra.push(h("p", {}, t(label)), h("pre", {}, location.origin + rt.replace(/\/?$/, "/") + "<id>"));
        }
      }
      body.append(h("h2", {}, t("doneTitle")), ...(proxyMode ? extra : [h("p", {}, t("doneLink")), h("pre", {}, link)]),
        h("div", { class: "row" }, h("button", { type: "button", onclick: async (ev) => {
          try { await navigator.clipboard.writeText(link); ev.target.textContent = t("copied"); } catch (e) { /* ignore */ }
        } }, t("copy"))), h("p", { class: "hint" }, t("goTabs")),
        h("div", { class: "row" }, h("button", { type: "button", onclick: () => { wiz.done = false; wiz.step = 0; drawEditor(); } }, t("wizTitle"))));
      return h("div", {}, nav, body);
    }

    if (wiz.step === 0) {
      const p = (cfg.panel = cfg.panel || {});
      const out = h("div", {}, wiz.connMsg || null);
      const fromRaw = p.source === "raw";
      const srcBtn = (val, label) => h("button", { type: "button", class: (p.source || "") === val ? "on" : "", "aria-pressed": String((p.source || "") === val),
        onclick: () => { if (val) p.source = val; else delete p.source; changed(); drawEditor(); } }, label);
      const srcSel = h("div", { class: "seg big", role: "group", "aria-label": t("sourceLabel") }, srcBtn("", t("sourceJson")), srcBtn("raw", t("sourceRaw")));
      const rawField = field(t(proxyMode ? "rawUrl" : "rawUrlNeeded"), bindText(p, "raw_url", { placeholder: "https://panel.example.com:2096/sub/" }), null, true);
      body.append(modeEditor(p, () => drawEditor()),
        ...(proxyMode ? [] : [h("div", { class: "src-pick" }, h("div", { class: "hint" }, t("sourceLabel")), srcSel)]),
        ...(fromRaw && !proxyMode ? [h("div", { class: "msg warn" }, t("rawWarn"))] : []),
        h("p", {}, t(proxyMode ? "proxyHelp" : fromRaw ? "s1helpRaw" : "s1help")),
        proxyMode ? field(t("jsonUrl"), bindText(p, "url", { placeholder: "https://panel.example.com:2096/json/" }), null, true)
          : fromRaw ? rawField
          : field(t("panelUrl"), bindText(p, "url", { placeholder: "https://panel.example.com:2096/json/" }), null, true),
        ...(proxyMode ? [formatFields(p)] : []),
        h("label", { class: "check" }, bindBool(p, "verify_tls", true), t("verifyTls")),
        h("div", { class: "row" }, h("button", { type: "button", onclick: async () => {
          out.replaceChildren(h("p", { class: "hint" }, t("running")));
          const r = await api("checks", { config: cfg });
          const rows = (r.data.checks || []).filter((c) => c.id.startsWith("panel"));
          wiz.connMsg = h("div", { class: "checks" }, rows.map((c) => h("div", { class: "check-row " + c.status }, h("span", { class: "ci" }, { ok: "✓", warn: "!", fail: "✗", skip: "–" }[c.status]), h("div", {}, checkText(c)))));
          out.replaceChildren(wiz.connMsg);
        } }, t("checkConn"))), out, proxyMode ? h("div", { class: "row" }, h("button", { type: "button", class: "primary", onclick: save }, t("saveFinish"))) : buttons());
    } else if (wiz.step === 1) {
      const subid = h("input", { type: "text", value: lastSubid, placeholder: t("subid"), "aria-label": t("subid"), autocomplete: "off" });
      const note = h("div", {});
      const showSample = () => {
        if (!sample) return;
        const first = sample.slice(0, 12);
        note.replaceChildren(h("div", { class: "msg ok" }, t("found", { n: sample.length })),
          h("ul", { class: "plain" }, first.map((c) => h("li", {}, String(c.remarks ?? "(no name)")))),
          sample.length > 12 ? h("p", { class: "hint" }, t("more", { n: sample.length - 12 })) : null);
      };
      body.append(h("p", {}, t("s2help")), h("div", { class: "row" }, subid, h("button", { type: "button", onclick: async () => {
        note.replaceChildren(h("p", { class: "hint" }, t("fetching")));
        lastSubid = subid.value.trim();
        const r = await api("sample", { subid: lastSubid, config: cfg });
        if (r.ok) { setSample(r.data.configs); drawSampleInfo(); runPreview(); drawEditor(); }
        else note.replaceChildren(h("div", { class: "msg err" }, r.data.error || "error"));
      } }, t("fetch"))), note, buttons(sample ? t("next") : t("skip")));
      showSample();
    } else if (wiz.step === 2) {
      const goal = (key, title, help, extra) => {
        const g = wiz[key];
        const box = h("div", { class: "goal" + (g.on ? " on" : "") });
        const matchNote = h("p", { class: "hint" });
        const upd = () => {
          const n = matchCount(g.items);
          matchNote.textContent = g.items.length ? (n === null ? t("noMatchSample") : t("matches", { n, m: sample.length })) : "";
        };
        box.append(h("label", { class: "check big" }, h("input", { type: "checkbox", checked: g.on, onchange: (e) => { g.on = e.target.checked; box.classList.toggle("on", g.on); } }), title),
          h("div", { class: "goal-body" }, h("p", { class: "hint" }, help), chipsInput(g.items, upd, t("chipsHint")), matchNote, extra ? extra() : null));
        upd();
        return box;
      };
      body.append(h("p", {}, t("s3help")),
        goal("hide", t("goalHide"), t("goalHideHelp")),
        goal("bal", t("goalBalance"), t("goalBalanceHelp"), () => h("div", {},
          field(t("balSplit"), h("input", { type: "text", value: wiz.bal.split, oninput: (e) => { wiz.bal.split = e.target.value; } })),
          field(t("balType"), (() => { const sel = h("select", { onchange: (e) => { wiz.bal.type = e.target.value; } },
            ["leastLoad", "leastPing", "random", "roundRobin"].map((x) => h("option", { value: x }, x))); sel.value = wiz.bal.type; return sel; })()),
          h("p", { class: "hint" }, t("balNote")))),
        buttons());
    } else {
      body.append(h("p", {}, t("s4help")));
      if (lastPreview && sample) {
        const o = lastPreview.output ? lastPreview.output.length : 0;
        body.append(h("p", { class: "big-note" }, t("beforeAfter", { a: sample.length, b: o })));
      }
      body.append(h("h3", {}, t("checksTitle")), checksView(),
        h("div", { class: "row" }, h("button", { type: "button", onclick: runChecks }, t("runChecks"))),
        h("div", { class: "row" }, h("button", { type: "button", onclick: () => goStep(2) }, t("back")),
          h("button", { type: "button", class: "primary", onclick: save }, t("saveFinish"))));
    }
    return h("div", {}, nav, body);
  }
  function goStep(i) {
    wiz.step = Math.max(0, Math.min(3, i));
    if (wiz.step === 3) { applyGoals(); wiz.checks = null; runChecks(); return; }
    drawEditor();
  }

  // ---------- main layout ----------
  const statusEl = h("span", { class: "status" });
  const restartHeaderBtn = h("button", { type: "button", class: "restart-btn", onclick: () => restartService() });
  function updateRestartBtn() {
    restartHeaderBtn.textContent = t("restartBtn");
    restartHeaderBtn.classList.toggle("needed", needsRestart());
    restartHeaderBtn.title = needsRestart() ? t("restartNeeded") : "";
  }
  const editorEl = h("section", { class: "card" });
  const previewEl = h("section", { class: "card preview" });

  function setStatus(text, cls) { statusEl.textContent = text; statusEl.className = "status " + (cls || ""); }
  // editors create empty lists and objects just by being shown; those are not changes
  const prune = (v) => {
    if (Array.isArray(v)) return v.map(prune);
    if (!v || typeof v !== "object") return v;
    const o = {};
    for (const [k, x] of Object.entries(v)) {
      const y = prune(x);
      if (Array.isArray(y) ? y.length : y && typeof y === "object" ? Object.keys(y).length : y !== undefined) o[k] = y;
    }
    return o;
  };
  let savedPruned = null, savedPrunedFor = null;
  function isDirty() {
    if (savedPrunedFor !== savedSnapshot) { savedPruned = JSON.stringify(prune(JSON.parse(savedSnapshot))); savedPrunedFor = savedSnapshot; }
    return JSON.stringify(prune(cfg)) !== savedPruned;
  }
  function changed() {
    updateRestartBtn();
    if (isDirty()) setStatus(t("unsaved"), "dirty"); else setStatus("", "");
    schedulePreview();
  }


  // ---------- expand (copies per server) ----------
  function expandEditor(g) {
    const box = h("div", { class: "opt" });
    function draw() {
      box.replaceChildren();
      const on = g.expand && typeof g.expand === "object";
      const cb = h("input", { type: "checkbox", checked: !!on, onchange: () => {
        if (cb.checked) g.expand = { copies: 2 }; else delete g.expand;
        changed(); draw();
      } });
      box.append(h("label", { class: "check" }, cb, t("expandOn")));
      if (!on) return;
      const ex = g.expand;
      const sb = ex.server_by && typeof ex.server_by === "object" ? ex.server_by : {};
      const updSb = () => { if (sb.regex) ex.server_by = { field: sb.field || "remark", regex: sb.regex }; else delete ex.server_by; changed(); };
      const addrs = Array.isArray(ex.addresses) ? ex.addresses : [];
      box.append(
        h("div", { class: "grid" },
          field(t("exCopies"), bindText(ex, "copies", { num: true, optional: false })),
          field(t("exLayout"), bindSelect(ex, "layout", [["", t("exGrouped")], ["grouped", t("exGrouped")], ["blocks", t("exBlocks")]])),
          field(t("exPick"), bindSelect(ex, "pick", [["", t("pickRandom")], ["random", t("pickRandom")], ["per_user", t("pickUser")]])),
          field(t("exServerBy"), h("input", { type: "text", list: "dl-fields", value: sb.field ?? "remark", oninput: (e) => { sb.field = e.target.value; updSb(); } })),
          field(t("exServerRegex"), h("input", { type: "text", value: sb.regex ?? "", oninput: (e) => { sb.regex = e.target.value; updSb(); } })),
          field(t("exAddrRegex"), bindText(ex, "address_regex"))),
        h("label", { class: "f wide" }, t("exAddresses"),
          chipsInput(addrs, () => { if (addrs.length) ex.addresses = addrs; else delete ex.addresses; changed(); }, "")),
        whenEditor(ex, "when", "exWhen"));
    }
    draw();
    return box;
  }

  // ---------- member patches: fragment and cipher-suite presets ----------
  const FRAG_KEY = "streamSettings.finalmask.tcp";
  const CS_KEY = "streamSettings.tlsSettings.cipherSuites";
  const isObj = (v) => !!v && typeof v === "object" && !Array.isArray(v);
  const strList = (v) => Array.isArray(v) && v.every((x) => typeof x === "string");
  const fragOk = (opts) => Array.isArray(opts) && opts.length > 0 && opts.every((pre) => Array.isArray(pre) && pre.length > 0 && pre.every((m) =>
    isObj(m) && m.type === "fragment" && isObj(m.settings) &&
    ["packets", "maxSplit"].every((k) => m.settings[k] === undefined || typeof m.settings[k] === "string") &&
    ["lengths", "delays"].every((k) => m.settings[k] === undefined || strList(m.settings[k]))));
  const csOk = (opts) => Array.isArray(opts) && opts.length > 0 && opts.every((x) => typeof x === "string");
  const patchOk = (p) => isObj(p) && Object.keys(p).every((k) => k === "when" || k === "merge" || k === "random") &&
    (p.merge === undefined || isObj(p.merge)) && (p.random === undefined || isObj(p.random));
  const canon = (v) => JSON.stringify(v, (k, x) => (isObj(x) ? Object.fromEntries(Object.keys(x).sort().map((q) => [q, x[q]])) : x));
  // the shared preset names (the same ones 3x-ui offers for hosts)
  const FRAG_TAIL = { type: "fragment", settings: { packets: "1-1", lengths: ["114", "1"], delays: ["1"], maxSplit: "11" } };
  const fragHead = (a, b) => ({ type: "fragment", settings: { packets: "tlshello", lengths: [a, b, "1"], delays: ["0"], maxSplit: "0" } });
  const FRAG_PRESETS = {
    "tlshello-0-len": [fragHead("0", "104"), FRAG_TAIL],
    "tlshello-6-98": [fragHead("6", "98"), FRAG_TAIL],
  };
  const CS_PRESETS = {
    "semi-python": ["TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
      "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"].join(":"),
    "real-firefox": ["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
      "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "TLS_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_AES_256_GCM_SHA384",
      "TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA"].join(":"),
  };
  const newStep = () => ({ type: "fragment", settings: { packets: "tlshello", lengths: ["0", "100"], delays: ["0"], maxSplit: "0" } });
  const fragLabel = (pre) => pre.map((m) => (m.settings.packets || "?") + " " + (m.settings.lengths || []).join(",")).join(" + ");
  const csLabel = (str) => { const n = str.split(":").filter(Boolean); return n.length ? n.length + " suites, " + n[0].replace(/^TLS_/, "") + " …" : "(empty)"; };

  // a list of presets, each in its own collapsible block
  function presetList(titleKey, opts, labelOf, bodyOf, makeNew, onChange, known) {
    const wrap = h("div", { class: "presets" });
    const open = new Set();
    const nameOf = (o) => Object.keys(known || {}).find((k) => canon(known[k]) === canon(o));
    const draw = () => {
      wrap.replaceChildren(h("h4", {}, t(titleKey)));
      opts.forEach((o, i) => {
        const d = h("details", { class: "more" }, h("summary", {}, (i + 1) + ". " + (nameOf(o) || labelOf(o))),
          bodyOf(o, i, () => onChange(), draw),
          h("div", { class: "row" }, h("button", { type: "button", class: "danger", onclick: () => { open.clear(); opts.splice(i, 1); onChange(); draw(); } }, t("remove"))));
        d.open = open.has(i);
        d.addEventListener("toggle", () => { if (d.open) open.add(i); else open.delete(i); });
        wrap.append(d);
      });
      const names = Object.keys(known || {}).filter((k) => !opts.some((o) => canon(o) === canon(known[k])));
      const sel = h("select", { class: "add-from", onchange: () => {
        const v = sel.value;
        if (!v) return;
        open.add(opts.length);
        opts.push(v === "__custom" ? makeNew() : JSON.parse(JSON.stringify(known[v])));
        onChange(); draw();
      } }, h("option", { value: "" }, t("mpAddPreset")), names.map((k) => h("option", { value: k }, k)), h("option", { value: "__custom" }, t("mpCustom")));
      wrap.append(sel);
    };
    draw();
    return wrap;
  }
  const listInput = (obj, key) => h("input", { type: "text", value: (obj[key] || []).join(", "), oninput: (e) => {
    const v = e.target.value.split(/[,\s]+/).filter(Boolean);
    if (v.length) obj[key] = v; else delete obj[key];
    changed();
  } });
  const fragBody = (pre, i, change, redraw) => h("div", {},
    pre.map((m, j) => h("div", { class: "grid step" },
      field("packets", bindText(m.settings, "packets")),
      field("lengths", listInput(m.settings, "lengths")),
      field("delays", listInput(m.settings, "delays")),
      field("maxSplit", bindText(m.settings, "maxSplit")),
      pre.length > 1 ? h("button", { type: "button", class: "danger", onclick: () => { pre.splice(j, 1); change(); redraw(); } }, t("mpRemoveStep")) : null)),
    h("button", { type: "button", onclick: () => { pre.push(newStep()); change(); redraw(); } }, t("mpAddStep")));
  const csBody = (str, i, change, redraw, opts) => {
    const ta = h("textarea", { rows: 6, spellcheck: "false" });
    ta.value = str.split(":").filter(Boolean).join("\n");
    ta.addEventListener("input", () => { opts[i] = ta.value.split(/[:\s,]+/).filter(Boolean).join(":"); change(); });
    return h("div", {}, ta, h("p", { class: "hint" }, t("mpCipherHint")));
  };

  function randomEditor(p) {
    const box = h("div", { class: "opt" });
    const commit = (key, opts) => {
      if (opts.length) { p.random = p.random || {}; p.random[key] = opts; }
      else if (p.random) { delete p.random[key]; if (!Object.keys(p.random).length) delete p.random; }
      changed();
    };
    function draw() {
      box.replaceChildren(h("h4", {}, t("mpRandom")), h("p", { class: "hint" }, t("mpRandomHint")));
      const rnd = isObj(p.random) ? p.random : {};
      const handled = new Set();
      const kinds = [
        [FRAG_KEY, fragOk, "mpFragment", "mpAddFragment", fragLabel, fragBody, () => [newStep()], FRAG_PRESETS],
        [CS_KEY, csOk, "mpCipher", "mpAddCipher", csLabel, (str, i, change, redraw, opts) => csBody(str, i, change, redraw, opts), () => "", CS_PRESETS],
      ];
      for (const [key, ok, titleKey, addKey, label, body, make, known] of kinds) {
        if (ok(rnd[key])) {
          handled.add(key);
          const opts = rnd[key];
          box.append(presetList(titleKey, opts, label, (o, i, change, redraw) => body(o, i, change, redraw, opts), make, () => { commit(key, opts); if (!opts.length) draw(); }, known));
        } else if (rnd[key] === undefined) {
          box.append(h("div", { class: "row" }, h("button", { type: "button", onclick: () => { const first = Object.values(known)[0]; commit(key, [first ? JSON.parse(JSON.stringify(first)) : make()]); draw(); } }, t(addKey))));
        }
      }
      const rest = Object.fromEntries(Object.entries(rnd).filter(([k]) => !handled.has(k)));
      const ta = h("textarea", { rows: 4, spellcheck: "false" });
      ta.value = Object.keys(rest).length ? JSON.stringify(rest, null, 2) : "";
      ta.addEventListener("input", () => {
        const txt = ta.value.trim();
        let parsed = {};
        if (txt) { try { parsed = JSON.parse(txt); } catch (e) { ta.classList.add("bad"); return; } if (!isObj(parsed)) { ta.classList.add("bad"); return; } }
        ta.classList.remove("bad");
        const keep = Object.fromEntries(Object.entries(isObj(p.random) ? p.random : {}).filter(([k]) => handled.has(k)));
        const all = Object.assign(keep, parsed);
        if (Object.keys(all).length) p.random = all; else delete p.random;
        changed();
      });
      box.append(h("details", { class: "more" }, h("summary", {}, t("mpOther")), ta));
    }
    draw();
    return box;
  }

  const OPEN_PATCHES = new WeakSet();
  function memberPatchEditor(g) {
    const box = h("div", { class: "mp" });
    let mode = g.member_patch === undefined || (Array.isArray(g.member_patch) && g.member_patch.every(patchOk)) ? "form" : "json";
    function draw() {
      box.replaceChildren();
      const head = h("div", { class: "row" }, h("h3", {}, t("mpTitle")));
      head.append(h("button", { type: "button", onclick: () => {
        if (mode === "form") { mode = "json"; draw(); }
        else if (g.member_patch === undefined || (Array.isArray(g.member_patch) && g.member_patch.every(patchOk))) { mode = "form"; draw(); }
        else alert(t("mpNotForm"));
      } }, mode === "form" ? t("mpEditJson") : t("mpEditForm")));
      box.append(head, h("p", { class: "hint" }, t("mpHint")));
      if (mode === "json") { box.append(bindJSON(g, "member_patch", 8)); return; }
      const list = g.member_patch || [];
      const set = () => { if (list.length) g.member_patch = list; else delete g.member_patch; changed(); };
      list.forEach((p, idx) => {
        const move = (d) => { const j = idx + d; if (j < 0 || j >= list.length) return; [list[idx], list[j]] = [list[j], list[idx]]; set(); draw(); };
        const card = h("details", { class: "sect" },
          h("summary", {}, t("mpPatch") + " " + (idx + 1) + ": " + (p.when ? describeWhen(p.when) : t("mpAll"))),
          whenEditor(p),
          h("div", { class: "f wide" }, t("mpMerge"), mergeEditor(p, "merge"), h("span", { class: "hint" }, t("mpMergeHint"))),
          randomEditor(p),
          h("div", { class: "row" },
            h("button", { type: "button", onclick: () => move(-1), "aria-label": "↑" }, "↑"),
            h("button", { type: "button", onclick: () => move(1), "aria-label": "↓" }, "↓"),
            h("button", { type: "button", class: "danger", onclick: () => { if (confirm(t("confirmDel"))) { list.splice(idx, 1); set(); draw(); } } }, t("remove"))));
        card.open = OPEN_PATCHES.has(p);
        card.addEventListener("toggle", () => { if (card.open) OPEN_PATCHES.add(p); else OPEN_PATCHES.delete(p); });
        box.append(card);
      });
      box.append(h("button", { type: "button", onclick: () => { const p = {}; OPEN_PATCHES.add(p); list.push(p); set(); draw(); } }, t("mpAdd")));
    }
    draw();
    return box;
  }

  // ---------- blocks: the drag-and-drop builder ----------
  const B_SETTINGS = [
    { key: "warp", kind: "one", options: ["exit", "only"], labels: { exit: "bWarpExit", only: "bWarpOnly" }, def: "exit", types: ["warp"] },
    { key: "pick", kind: "one", options: ["random", "per_user"], labels: { random: "bPickRandom", per_user: "bPickUser" }, def: "random", types: ["warp"] },
    { key: "decoy", kind: "one", options: ["vless"], labels: { vless: "bDecoyVless" }, def: "vless", types: ["warp"] },
    { key: "fragment", kind: "multi", options: ["tlshello-0-len", "tlshello-6-98"], def: ["tlshello-0-len", "tlshello-6-98"], ph: "bCustomFrag", add: "bAddCustom", types: ["list", "balancer"] },
    { key: "cipher", kind: "multi", options: ["semi-python", "real-firefox"], def: ["semi-python", "real-firefox"], ph: "bCustomCipher", add: "bAddCustom", types: ["list", "balancer"] },
    { key: "fingerprint", kind: "one", options: ["chrome", "firefox", "safari", "ios", "android", "edge", "random", "randomized"], def: "chrome", types: ["list", "balancer"] },
    { key: "strategy", kind: "one", options: ["leastLoad", "leastPing", "random", "roundRobin"], def: "leastLoad", types: ["balancer"] },
    // the parameters of the chosen strategy are edited inside the Strategy setting (see bStrategyFields), not as settings of their own
    { key: "load", kind: "fields", hidden: true, def: {}, types: ["balancer"] },
    { key: "probe", kind: "fields", hidden: true, def: {}, types: ["balancer"] },
    { key: "cost", kind: "fields", hidden: true, def: [], types: ["balancer"] },
    { key: "member_position", kind: "custom", def: [{ at: "last" }], types: ["balancer"] },
    { key: "member_patch", kind: "custom", def: [], types: ["balancer"] },
    { key: "catchall_rules", kind: "custom", def: [{ network: "tcp,udp" }], types: ["balancer"] },
    { key: "min_members", kind: "num", def: 2, types: ["balancer"] },
    { key: "keep_members", kind: "one", options: ["keep"], labels: { keep: "bKeepMembers" }, def: true, types: ["balancer"] },
    { key: "include_balanced", kind: "one", options: ["include"], labels: { include: "bIncludeBalanced" }, def: true, types: ["balancer"] },
    { key: "probe_kind", kind: "one", options: ["burst", "observatory"], labels: { burst: "burstObservatory", observatory: "observatory" }, def: "burst", types: ["balancer"] },
    { key: "position", kind: "one", options: ["top", "bottom"], labels: { top: "bPosTop", bottom: "bPosBottom" }, def: "top", types: ["balancer", "warp"] },
    { key: "remove_exit", kind: "one", options: ["remove"], labels: { remove: "bRemoveExit" }, def: true, types: ["warp"] },
    { key: "expand", kind: "custom", def: { copies: 2 }, types: ["balancer"] },
    { key: "entry_merge", kind: "custom", def: {}, types: ["warp"] },
    { key: "choices", kind: "custom", def: { endpoint: ["1.2.3.4", "5.6.7.8"] }, types: ["warp"] },
    { key: "entry", kind: "custom", def: "{account.masque.outbound}", types: ["warp"] },
    { key: "endpoints", kind: "custom", def: "{account.masque.endpoints}", types: ["warp"] },
    { key: "patches", kind: "custom", def: [], types: ["list"] },
    { key: "pool", kind: "list", def: ["a.example.com", "b.example.com"], ph: "bAddressPh", add: "bAddAddress", types: ["balancer"] },
    { key: "name", kind: "text", def: "{block} {country}", types: ["list", "balancer", "warp"] },
  ];
  const bType = (blk) => blk.type || "list";
  const bAllowed = (d, blk) => d.types.includes(bType(blk));
  const bNameDefault = (blk) => (bType(blk) === "list" ? "{block} {n}" : blk.per_country ? "{block} {country}" : "{block}");
  const bTokens = (blk) => (bType(blk) === "list" ? ["{block}", "{name}", "{country}", "{n}"] : ["{block}", "{country}", "{n}"]);
  const bLabel = (d, v) => (d.labels && d.labels[v] ? t(d.labels[v]) : String(v));
  const B_ADV_HINT = { balancer: "bAdvBalancer", list: "bAdvList", warp: "bAdvWarp" };
  const B_DEF = Object.fromEntries(B_SETTINGS.map((x) => [x.key, x]));
  const bEmpty = () => ({ rest: "keep", list: [] });
  const bView = () => (isObj(cfg.blocks) && Array.isArray(cfg.blocks.list) ? cfg.blocks : bEmpty());
  const condOnly = (w) => Object.fromEntries(Object.entries(w || {}).filter(([k]) => !k.startsWith("_")));
  const kkey = (w) => canon(condOnly(w));
  let bSel = [], bSelLast = -1;   // several sample kinds selected (Ctrl/Cmd+click toggles, Shift+click selects a range)
  let bKinds = null, bKindsFor = null, bPick = null, bDrag = null, bOver = null, bOpen = null, bMenu = null, bDraft = "";
  let bPast = [], bFuture = [];
  const bNewCond = {};
  let bTestOpen = false, bTestIds = "", bTestResult = null, bTestBusy = false;
  const maskId = (x) => (x.length > 4 ? x.slice(0, 4) + "…" : x);
  async function bRunTest() {
    const ids = [...new Set(bTestIds.split(/[\s,]+/).filter(Boolean))].slice(0, 10);
    if (!ids.length) return;
    bTestBusy = true; bTestResult = []; drawEditor();
    for (const id of ids) {
      const row = { id: maskId(id) };
      const sres = await api("sample", { subid: id, config: cfg });
      if (!sres.ok) { row.error = sres.data.error || "error"; bTestResult.push(row); continue; }
      const configs = sres.data.configs;
      const p = await api("preview", { config: cfg, configs, subid: id });
      if (!p.ok) { row.error = "preview failed"; bTestResult.push(row); continue; }
      const rep = p.data.report || {};
      row.in = configs.length; row.out = p.data.output.length;
      row.errors = (p.data.errors || []).length + (rep.errors || []).length;
      row.unplaced = (rep.configs || []).filter((c) => c.action !== "drop" && !c.rule && !(c.groups || []).length && !(c.chains || []).length).length;
      bTestResult.push(row);
    }
    bTestBusy = false; drawEditor();
  }
  function bTestView() {
    const ta = h("textarea", { rows: 3, spellcheck: "false", placeholder: t("bTestPh"), "aria-label": t("bTestPh") });
    ta.value = bTestIds;
    ta.addEventListener("input", () => { bTestIds = ta.value; });
    return h("div", { class: "b-test" },
      h("p", { class: "hint" }, t("bTestHint")), ta,
      h("div", { class: "row" }, h("button", { type: "button", class: "primary", disabled: bTestBusy, onclick: bRunTest }, bTestBusy ? t("fetching") : t("bTestRun"))),
      bTestResult && bTestResult.length ? h("ul", { class: "sum-list" }, bTestResult.map((r) => h("li", { class: r.error || r.errors ? "sum-del" : "sum-add" },
        r.error ? t("bTestErr", { id: r.id, e: r.error })
          : t("bTestRow", { id: r.id, a: r.in, b: r.out, u: r.unplaced }) + (r.errors ? " · " + t("sumErrors", { n: r.errors }) : "")))) : null);
  }

  function bLoadKinds() {
    if (!sample || bKindsFor === sample) return;
    const want = sample;
    bKindsFor = sample;
    api("kinds", { configs: sample }).then((r) => {
      if (r.ok && want === sample) { bKinds = r.data.kinds; if (tab === "blocks") drawEditor(); }
    });
  }
  document.addEventListener("xsf-sample", () => { if (tab === "blocks") bLoadKinds(); });

  const B_SNAP = ["blocks", "groups", "rules", "chains"];
  const bSnap = () => JSON.stringify(B_SNAP.map((k) => (cfg[k] === undefined ? null : cfg[k])));
  function bChange(fn, keepOpen) {
    bPast.push(bSnap());
    if (bPast.length > 100) bPast.shift();
    bFuture = [];
    if (!isObj(cfg.blocks) || !Array.isArray(cfg.blocks.list)) cfg.blocks = bEmpty();
    fn(cfg.blocks);
    bPick = null; bOver = null; bDrag = null; bSel = []; bSelLast = -1;
    if (!keepOpen) bDraft = "";
    changed(); drawEditor();
  }
  function bRestore(snap) {
    JSON.parse(snap).forEach((v, n) => { const k = B_SNAP[n]; if (v === null) delete cfg[k]; else cfg[k] = v; });
    changed(); drawEditor();
  }
  function bMove(cond, target, fromSource) {   // cond: one kind or an array of them; target: a block index, "trash" or "rest"
    const conds = (Array.isArray(cond) ? cond : [cond]).filter(Boolean);
    if (!conds.length) return;
    bChange((b) => {
      const toBalancer = typeof target === "number" && b.list[target] && b.list[target].type === "balancer";
      for (const one of conds) {
        const key = kkey(one);
        b.list.forEach((x, n) => {
          if (fromSource && toBalancer && x.type === "balancer" && n !== target) return;   // a copy: the other balancers keep it
          x.kinds = (x.kinds || []).filter((w) => kkey(w) !== key);
        });
      }
      if (target === "rest") return;
      let i = target;
      if (target === "trash") {
        i = b.list.findIndex((x) => x.type === "drop");
        if (i < 0) { b.list.push({ id: nextId("removed", b.list), type: "drop", kinds: [] }); i = b.list.length - 1; }
      }
      b.list[i].kinds = (b.list[i].kinds || []).concat(conds.map((c) => JSON.parse(JSON.stringify(c))));
    });
  }
  // what a "Move here" / "Remove" press moves: the selected kinds, else the single picked one
  const bPicked = () => (bSel.length && bKinds ? bKinds.filter((k) => bSel.includes(kkey(k.when))).map(bCond) : bPick);
  const bHasPick = () => !!(bSel.length || bPick);
  const bCond = (k) => Object.assign({ _label: (k.flag ? k.flag + " " : "") + k.label }, k.when);
  let bDragSource = false;
  function bDragProps(cond, fromSource) {
    return { draggable: "true", ondragstart: (e) => { bDrag = cond; bDragSource = !!fromSource; try { e.dataTransfer.setData("text/plain", "kind"); e.dataTransfer.effectAllowed = "move"; } catch (x) { /* ignore */ } },
      ondragend: () => { bDrag = null; if (bOver !== null) { bOver = null; drawEditor(); } } };
  }
  function bZone(target, el) {
    el.addEventListener("dragover", (e) => { if (!bDrag) return; e.preventDefault(); if (bOver !== target) { bOver = target; el.classList.add("over"); } });
    el.addEventListener("dragleave", (e) => { if (!el.contains(e.relatedTarget)) { el.classList.remove("over"); if (bOver === target) bOver = null; } });
    el.addEventListener("drop", (e) => { e.preventDefault(); el.classList.remove("over"); const c = bDrag; bDrag = null; bMove(c, target, bDragSource); });
    return el;
  }
  function bSummary(key, v) {
    const d = B_DEF[key];
    if (d.kind === "multi") return v.map((x) => (d.options.includes(x) ? x : t("bCustom"))).join(" · ") + (v.length > 1 ? ", " + t("bRandom") : "");
    if (key === "expand") return t("bExpandSum", { n: v.copies || 1 });
    if (key === "entry_merge") return t("bNPaths", { n: kvFlat(v, "", []).length });
    if (key === "choices") return t("bNLists", { n: Object.keys(v).length });
    if (key === "entry") return typeof v === "string" ? v : t("bNPaths", { n: kvFlat(v, "", []).length });
    if (key === "endpoints") return Array.isArray(v) ? t("bAddresses", { n: v.length }) : v;
    if (key === "patches") return t("bNPatches", { n: v.length });
    if (d.kind === "custom") return t(key === "member_patch" ? "bNSteps" : "bNRules", { n: v.length });
    if (d.kind === "list") return t("bAddresses", { n: v.length }) + (v.length > 1 ? ", " + t("bRandom") : "");
    if (d.kind === "num") return String(v);
    if (typeof d.def === "boolean") return bLabel(d, d.options[0]);
    return bLabel(d, v);
  }
  // Xray's two probes: leastLoad reads burstObservatory.pingConfig, leastPing reads observatory; only leastLoad has strategy settings
  const B_PROBE_DEFAULT = {
    leastLoad: { destination: "https://www.gstatic.com/generate_204", interval: "30s" },
    leastPing: { probeUrl: "https://www.gstatic.com/generate_204", probeInterval: "30s" },
  };
  const B_LOAD_FIELDS = [["expected", "num", ""], ["maxRTT", "text", "2500ms"], ["tolerance", "num", "0.01"], ["baselines", "list", "1s, 2s"]];
  const B_PROBE_FIELDS = {
    leastLoad: [["destination", "text", "https://www.gstatic.com/generate_204"], ["connectivity", "text", ""], ["interval", "text", "30s"], ["sampling", "num", "10"], ["timeout", "text", "5s"], ["httpMethod", "text", "HEAD"]],
    leastPing: [["probeUrl", "text", "https://www.gstatic.com/generate_204"], ["probeInterval", "text", "30s"], ["enableConcurrency", "bool", ""]],
  };
  const bStash = {};                 // block id -> {strategy: {load, probe, cost}} of the strategies switched away from
  const bCostOpen = new WeakSet();   // cost rows whose condition editor is open (new rows start open, the others folded)
  function bStrategyFields(blk, strategy) {
    const grid = (obj, fields, label) => {
      const set = (k, kind, raw) => {
        const val = raw.trim();
        if (val === "") delete obj[k];
        else if (kind === "num") obj[k] = Number(val);
        else if (kind === "bool") obj[k] = val === "true";
        else if (kind === "list") obj[k] = val.split(",").map((x) => x.trim()).filter(Boolean);
        else obj[k] = val;
        changed();
      };
      return h("div", {}, h("strong", { class: "hint" }, t(label)),
        h("div", { class: "grid" }, fields.map(([k, kind, ph]) => {
          const cur = obj[k];
          const input = kind === "bool"
            ? h("select", { "aria-label": k, onchange: (e) => set(k, kind, e.target.value) },
                ["", "true", "false"].map((o) => h("option", { value: o, selected: String(cur === undefined ? "" : cur) === o }, o || "—")))
            : h("input", { type: kind === "num" ? "number" : "text", step: "any", placeholder: ph, "aria-label": k,
                value: cur === undefined ? "" : Array.isArray(cur) ? cur.join(", ") : cur, oninput: (e) => set(k, kind, e.target.value) });
          return field(k, input);
        })));
    };
    // costs of members: the first rule that matches a member sets its cost (higher = used less); a rule without a condition is the default
    const costOpen = bCostOpen;
    const costEditor = (st) => {
      const box = h("div", {});
      const draw = () => {
        const list = Array.isArray(st.cost) ? st.cost : [];
        const sync = () => { if (list.length) st.cost = list; else delete st.cost; changed(); };
        box.replaceChildren(h("strong", { class: "hint" }, t("bCostTitle")), h("p", { class: "hint" }, t("bCostHint")),
          ...list.map((row, n) => {
            const open = costOpen.has(row);
            const summary = row.when && Object.keys(row.when).length ? describeWhen(row.when) : t("bCostAll");
            const move = (to) => { if (to >= 0 && to < list.length) { list.splice(to, 0, list.splice(n, 1)[0]); sync(); draw(); } };
            return h("div", { class: "b-costrow" },
              h("div", { class: "row" },
                h("input", { type: "number", step: "any", min: "0", class: "b-costval", value: row.value === undefined ? "" : row.value, "aria-label": t("bCostValue"), title: t("bCostValue"),
                  oninput: (e) => { row.value = e.target.value === "" ? 0 : Number(e.target.value); sync(); } }),
                h("button", { type: "button", class: "b-costwhen", "aria-expanded": String(open), title: summary,
                  onclick: () => { if (open) costOpen.delete(row); else costOpen.add(row); draw(); } }, summary, open ? " ▴" : " ▾"),
                h("button", { type: "button", class: "icon", "aria-label": t("bUp"), title: t("bUp"), disabled: n === 0, onclick: () => move(n - 1) }, "↑"),
                h("button", { type: "button", class: "icon", "aria-label": t("bDown"), title: t("bDown"), disabled: n === list.length - 1, onclick: () => move(n + 1) }, "↓"),
                h("button", { type: "button", class: "icon danger", "aria-label": t("bDelete"), title: t("bDelete"), onclick: () => { list.splice(n, 1); sync(); draw(); } }, "×")),
              ...(open ? [whenEditor(row, "when", "bCostWhen")] : []));
          }),
          h("button", { type: "button", class: "small", onclick: () => { st.cost = list; const row = { value: 1 }; list.push(row); costOpen.add(row); sync(); draw(); } }, t("bCostAdd")));
      };
      draw();
      return box;
    };
    const st = blk.settings;
    const parts = [];
    if (strategy === "leastLoad") {
      st.load = st.load || {};
      parts.push(grid(st.load, B_LOAD_FIELDS, "bLoadParams"));
      parts.push(costEditor(st));
    }
    if (B_PROBE_FIELDS[strategy]) { st.probe = st.probe || {}; parts.push(grid(st.probe, B_PROBE_FIELDS[strategy], "bProbeParams")); }
    if (!parts.length) parts.push(h("p", { class: "hint" }, t("bNoParams")));
    return h("div", { class: "b-params" }, ...parts);
  }

  // a merge object as rows "path = value" (nested keys joined by dots); a value is JSON when it parses, else text
  const kvFlat = (o, pre, out) => { Object.entries(o).forEach(([k, v]) => { if (isObj(v) && Object.keys(v).length) kvFlat(v, pre + k + ".", out); else out.push([pre + k, v]); }); return out; };
  const kvNest = (rows) => {
    const res = {};
    rows.forEach(([path, v]) => {
      const parts = path.trim().split(".").filter(Boolean);
      if (!parts.length) return;
      let o = res;
      parts.slice(0, -1).forEach((k) => { if (!isObj(o[k])) o[k] = {}; o = o[k]; });
      o[parts[parts.length - 1]] = v;
    });
    return res;
  };
  const kvText = (v) => { if (typeof v === "string") { try { JSON.parse(v); return JSON.stringify(v); } catch (e) { return v; } } return JSON.stringify(v); };
  const kvValue = (x) => { try { return JSON.parse(x); } catch (e) { return x; } };
  function mergeEditor(obj, key, keep) {
    const box = h("div", { class: "b-kv" });
    const rows = kvFlat(isObj(obj[key]) ? obj[key] : {}, "", []);
    const commit = () => { const o = kvNest(rows); if (Object.keys(o).length || keep) obj[key] = o; else delete obj[key]; changed(); };
    const draw = () => {
      box.replaceChildren(...rows.map((row, n) => h("div", { class: "row" },
        h("input", { type: "text", class: "mono b-kvpath", value: row[0], placeholder: t("kvPath"), "aria-label": t("kvPath"), oninput: (e) => { row[0] = e.target.value; commit(); } }),
        h("span", { class: "dim" }, "="),
        h("input", { type: "text", class: "mono b-kvval", value: kvText(row[1]), placeholder: t("kvValue"), "aria-label": t("kvValue"), oninput: (e) => { row[1] = kvValue(e.target.value); commit(); } }),
        h("button", { type: "button", class: "icon danger", "aria-label": t("bDelete"), title: t("bDelete"), onclick: () => { rows.splice(n, 1); commit(); draw(); } }, "×"))),
        h("button", { type: "button", class: "small", onclick: () => { rows.push(["", ""]); draw(); } }, t("kvAdd")),
        h("span", { class: "hint" }, t("kvHint")));
    };
    draw();
    return box;
  }
  // routing rules sent to the balancer: one card per rule with the usual fields; any other key of a rule is kept untouched
  const RULE_FIELDS = [["network", "text", "tcp,udp"], ["port", "text", "0-65535"], ["protocol", "list", "http, tls, bittorrent"],
    ["domain", "list", "geosite:google"], ["ip", "list", "geoip:private"], ["inboundTag", "list", "tag"], ["source", "list", "10.0.0.0/8"], ["sourcePort", "text", "1000-2000"]];
  const ROUTE_FIELDS = RULE_FIELDS.concat([["outboundTag", "text", "direct"], ["balancerTag", "text", ""]]);
  function catchallEditor(st, key = "catchall_rules", newRule = { network: "tcp,udp" }, keepEmpty = false, fields = RULE_FIELDS) {
    const box = h("div", {});
    const draw = () => {
      const list = Array.isArray(st[key]) ? st[key] : [];
      const sync = () => { if (list.length || !keepEmpty) st[key] = list; else delete st[key]; changed(); };
      box.replaceChildren(...list.map((rule, n) => {
        const move = (to) => { if (to >= 0 && to < list.length) { list.splice(to, 0, list.splice(n, 1)[0]); sync(); draw(); } };
        const set = (k, kind, raw) => {
          const v = raw.trim();
          if (!v) delete rule[k]; else rule[k] = kind === "list" ? v.split(",").map((x) => x.trim()).filter(Boolean) : v;
          sync();
        };
        const other = Object.keys(rule).filter((k) => k !== "type" && !fields.some((f) => f[0] === k));
        return h("div", { class: "b-costrow" },
          h("div", { class: "row" }, h("strong", { class: "hint", style: "flex:1" }, t("bRule") + " " + (n + 1)),
            h("button", { type: "button", class: "icon", "aria-label": t("bUp"), title: t("bUp"), disabled: n === 0, onclick: () => move(n - 1) }, "↑"),
            h("button", { type: "button", class: "icon", "aria-label": t("bDown"), title: t("bDown"), disabled: n === list.length - 1, onclick: () => move(n + 1) }, "↓"),
            h("button", { type: "button", class: "icon danger", "aria-label": t("bDelete"), title: t("bDelete"), disabled: !keepEmpty && list.length === 1, onclick: () => { list.splice(n, 1); sync(); draw(); } }, "×")),
          h("div", { class: "grid" }, fields.map(([k, kind, ph]) => field(k, h("input", { type: "text", placeholder: ph, "aria-label": k,
            value: Array.isArray(rule[k]) ? rule[k].join(", ") : rule[k] === undefined ? "" : rule[k], oninput: (e) => set(k, kind, e.target.value) })))),
          other.length ? h("p", { class: "hint" }, t("bRuleKept", { k: other.join(", ") })) : null);
      }), h("button", { type: "button", class: "small", onclick: () => { list.push(Object.assign({}, newRule)); sync(); draw(); } }, t("bRuleAdd")));
    };
    draw();
    return box;
  }

  // patches of a list block: when (inside the block), stage, target, merge, and routing rules added before / after
  const OPEN_BP = new WeakSet();
  function patchesEditor(st) {
    const box = h("div", {});
    const draw = () => {
      const list = Array.isArray(st.patches) ? st.patches : [];
      const sync = () => { st.patches = list; changed(); };
      box.replaceChildren(...list.map((p, n) => {
        const move = (to) => { if (to >= 0 && to < list.length) { list.splice(to, 0, list.splice(n, 1)[0]); sync(); draw(); } };
        const sel = (k, opts) => h("select", { "aria-label": k, onchange: (e) => { if (e.target.value) p[k] = e.target.value; else delete p[k]; sync(); } },
          opts.map(([v, label]) => h("option", { value: v, selected: (p[k] || "") === v }, label)));
        const card = h("details", { class: "sect" },
          h("summary", {}, t("mpPatch") + " " + (n + 1) + ": " + (p.when ? describeWhen(p.when) : t("mpAll"))),
          whenEditor(p),
          h("div", { class: "grid" },
            field(t("stage"), sel("stage", [["", t("source")], ["output", t("output")]])),
            field(t("target"), sel("target", [["", t("config")], ["outbound", t("outbound")]]))),
          h("div", { class: "f wide" }, t("pMerge"), mergeEditor(p, "merge"), h("span", { class: "hint" }, t("mpMergeHint"))),
          h("div", { class: "f wide" }, t("pRoutePre"), catchallEditor(p, "routing_prepend", { outboundTag: "direct" }, true, ROUTE_FIELDS)),
          h("div", { class: "f wide" }, t("pRoutePost"), catchallEditor(p, "routing_append", { outboundTag: "direct" }, true, ROUTE_FIELDS)),
          Object.keys(p).some((k) => k === "random") ? h("p", { class: "hint" }, t("bRuleKept", { k: "random" })) : null,
          h("div", { class: "row" },
            h("button", { type: "button", class: "icon", "aria-label": t("bUp"), disabled: n === 0, onclick: () => move(n - 1) }, "↑"),
            h("button", { type: "button", class: "icon", "aria-label": t("bDown"), disabled: n === list.length - 1, onclick: () => move(n + 1) }, "↓"),
            h("button", { type: "button", class: "danger", onclick: () => { list.splice(n, 1); sync(); draw(); } }, t("remove"))));
        card.open = OPEN_BP.has(p);
        card.addEventListener("toggle", () => { if (card.open) OPEN_BP.add(p); else OPEN_BP.delete(p); });
        return card;
      }), h("button", { type: "button", class: "small", onclick: () => { const p = {}; OPEN_BP.add(p); list.push(p); sync(); draw(); } }, t("mpAdd")));
    };
    draw();
    return box;
  }
  // WARP chain: the lists a user is spread over ("choices"), the entry outbound, and the endpoints
  function choicesEditor(st) {
    const box = h("div", {});
    const draw = () => {
      const rows = Object.entries(isObj(st.choices) ? st.choices : {});
      const commit = () => { const o = {}; rows.forEach(([k, v]) => { if (k.trim()) o[k.trim()] = v; }); st.choices = o; changed(); };
      box.replaceChildren(...rows.map((row, n) => h("div", { class: "row" },
        h("input", { type: "text", class: "mono b-kvpath", value: row[0], placeholder: t("chName"), "aria-label": t("chName"), oninput: (e) => { row[0] = e.target.value; commit(); } }),
        h("span", { class: "dim" }, "="),
        h("input", { type: "text", class: "mono b-kvval", value: row[1].map(kvText).join(", "), placeholder: "1.2.3.4, 5.6.7.8", "aria-label": t("chValues"),
          oninput: (e) => { row[1] = e.target.value.split(",").map((x) => x.trim()).filter(Boolean).map(kvValue); commit(); } }),
        h("button", { type: "button", class: "icon danger", "aria-label": t("bDelete"), onclick: () => { rows.splice(n, 1); commit(); draw(); } }, "×"))),
        h("button", { type: "button", class: "small", onclick: () => { rows.push(["", []]); draw(); } }, t("chAdd")));
    };
    draw();
    return box;
  }
  function entryEditor(st) {
    const box = h("div", {});
    const draw = () => {
      const asText = typeof st.entry === "string";
      const mode = h("select", { "aria-label": t("s_entry"), onchange: (e) => { st.entry = e.target.value === "text" ? "{account.masque.outbound}" : { protocol: "masque" }; changed(); draw(); } },
        h("option", { value: "text", selected: asText }, t("entryText")), h("option", { value: "obj", selected: !asText }, t("entryObj")));
      box.replaceChildren(mode, asText
        ? h("input", { type: "text", class: "mono", value: st.entry, "aria-label": t("s_entry"), oninput: (e) => { st.entry = e.target.value; changed(); } })
        : mergeEditor(st, "entry", true));
    };
    draw();
    return box;
  }
  function endpointsEditor(st) {
    const cur = Array.isArray(st.endpoints) ? st.endpoints.join(", ") : st.endpoints || "";
    return h("input", { type: "text", class: "mono", value: cur, placeholder: "{account.masque.endpoints}  /  host:port, host:port", "aria-label": t("s_endpoints"),
      oninput: (e) => { const v = e.target.value.trim(); st.endpoints = v.startsWith("{") ? v : v.split(",").map((x) => x.trim()).filter(Boolean); changed(); } });
  }

  // Advanced keys that have a setting of their own: moved there (same result, nothing else changes)
  function bMovable(blk) {
    const g = (blk.advanced && blk.advanced.group) || {}, st = blk.settings || {}, strat = st.strategy || "leastLoad";
    if (bType(blk) === "warp") {
      const c = (blk.advanced && blk.advanced.chain) || {};
      const w = [];
      if (isObj(c.entry_merge) && !(isObj(st.entry_merge) && Object.keys(st.entry_merge).length)) w.push(["entry_merge", "entry_merge"]);
      if (["top", "bottom"].includes(c.position) && st.position === undefined) w.push(["position", "position"]);
      if (c.remove_exit_from_output === true && st.remove_exit === undefined) w.push(["remove_exit_from_output", "remove_exit"]);
      if (isObj(c.choices) && Object.values(c.choices).every((x) => Array.isArray(x) && x.length) && !(isObj(st.choices) && Object.keys(st.choices).length)) w.push(["choices", "choices"]);
      if ((typeof c.entry === "string" || (isObj(c.entry) && Object.keys(c.entry).length)) && st.entry === undefined) w.push(["entry", "entry"]);
      if ((typeof c.endpoints === "string" || (Array.isArray(c.endpoints) && c.endpoints.length && c.endpoints.every((x) => typeof x === "string"))) && st.endpoints === undefined) w.push(["endpoints", "endpoints"]);
      return w;
    }
    const fits = (obj, fields) => isObj(obj) && Object.keys(obj).every((k) => {
      const f = fields.find((x) => x[0] === k);
      return f && (f[1] === "num" ? typeof obj[k] === "number" : f[1] === "bool" ? typeof obj[k] === "boolean" : f[1] === "list" ? Array.isArray(obj[k]) : typeof obj[k] === "string");
    });
    const out = [], free = (v) => v === undefined || (isObj(v) && !Object.keys(v).length) || (Array.isArray(v) && !v.length);
    if (g.params !== undefined && free(st.load) && strat === "leastLoad" && fits(g.params, B_LOAD_FIELDS)) out.push(["params", "load"]);
    if (g.probe !== undefined && free(st.probe) && B_PROBE_FIELDS[strat] && fits(g.probe, B_PROBE_FIELDS[strat])) out.push(["probe", "probe"]);
    if (g.member_cost !== undefined && free(st.cost) && strat === "leastLoad" && Array.isArray(g.member_cost)) out.push(["member_cost", "cost"]);
    if (g.member_position !== undefined && free(st.member_position)) out.push(["member_position", "member_position"]);
    if (g.catchall_rules !== undefined && free(st.catchall_rules)) out.push(["catchall_rules", "catchall_rules"]);
    if (g.expand !== undefined && isObj(g.expand) && free(st.expand)) out.push(["expand", "expand"]);
    if (typeof g.min_members === "number" && g.min_members >= 1 && st.min_members === undefined) out.push(["min_members", "min_members"]);
    if (g.position !== undefined && ["top", "bottom"].includes(g.position) && st.position === undefined) out.push(["position", "position"]);
    if (g.include_balanced === true && st.include_balanced === undefined) out.push(["include_balanced", "include_balanced"]);
    if (["burst", "observatory"].includes(g.probe_kind) && st.probe_kind === undefined) out.push(["probe_kind", "probe_kind"]);
    if (g.remove_members_from_output === false && st.keep_members === undefined) out.push(["remove_members_from_output", "keep_members", true]);
    return out;
  }
  function bMoveAdvanced(i) {
    bChange((b) => {
      const x = b.list[i], moves = bMovable(x);
      x.settings = x.settings || {};
      const src = bType(x) === "warp" ? "chain" : "group";
      moves.forEach(([from, to, val]) => { x.settings[to] = val !== undefined ? val : x.advanced[src][from]; delete x.advanced[src][from]; });
      if (isObj(x.advanced[src]) && !Object.keys(x.advanced[src]).length) delete x.advanced[src];
      if (Array.isArray(x.advanced.member_patch) && !(x.settings.member_patch || []).length) { x.settings.member_patch = x.advanced.member_patch; delete x.advanced.member_patch; }
      if (Array.isArray(x.advanced.patches) && !(x.settings.patches || []).length) { x.settings.patches = x.advanced.patches; delete x.advanced.patches; }
      if (!Object.keys(x.advanced).length) delete x.advanced;
    }, true);
  }

  // where matching members sit in the balancer: the first rule that matches a member decides (first = front, last = back)
  function positionEditor(st) {
    const box = h("div", {});
    const draw = () => {
      const list = Array.isArray(st.member_position) ? st.member_position : [];
      const sync = () => { if (list.length) st.member_position = list; else delete st.member_position; changed(); };
      box.replaceChildren(...list.map((row, n) => {
        const open = bCostOpen.has(row);
        const summary = row.when && Object.keys(row.when).length ? describeWhen(row.when) : t("bCostAll");
        const move = (to) => { if (to >= 0 && to < list.length) { list.splice(to, 0, list.splice(n, 1)[0]); sync(); draw(); } };
        return h("div", { class: "b-costrow" },
          h("div", { class: "row" },
            h("select", { class: "b-costval b-posat", "aria-label": t("bPosAt"), onchange: (e) => { row.at = e.target.value; sync(); } },
              ["first", "last"].map((o) => h("option", { value: o, selected: row.at === o }, t("bPos_" + o)))),
            h("button", { type: "button", class: "b-costwhen", "aria-expanded": String(open), title: summary,
              onclick: () => { if (open) bCostOpen.delete(row); else bCostOpen.add(row); draw(); } }, summary, open ? " ▴" : " ▾"),
            h("button", { type: "button", class: "icon", "aria-label": t("bUp"), title: t("bUp"), disabled: n === 0, onclick: () => move(n - 1) }, "↑"),
            h("button", { type: "button", class: "icon", "aria-label": t("bDown"), title: t("bDown"), disabled: n === list.length - 1, onclick: () => move(n + 1) }, "↓"),
            h("button", { type: "button", class: "icon danger", "aria-label": t("bDelete"), title: t("bDelete"), onclick: () => { list.splice(n, 1); sync(); draw(); } }, "×")),
          ...(open ? [whenEditor(row, "when", "bCostWhen")] : []));
      }), h("button", { type: "button", class: "small", onclick: () => { st.member_position = list; const row = { at: "last" }; list.push(row); bCostOpen.add(row); sync(); draw(); } }, t("bPosAdd")));
    };
    draw();
    return box;
  }

  function bSettingEditor(blk, i, key) {
    const d = B_DEF[key], v = blk.settings[key];
    const put = (nv) => bChange((b) => { b.list[i].settings[key] = nv; }, true);
    const box = h("div", { class: "b-editor" },
      h("div", { class: "row" }, h("strong", {}, t("s_" + key)), h("span", { class: "hint", style: "flex:1" }, t("h_" + key)),
        h("button", { type: "button", class: "small", onclick: () => put(d.key === "name" ? bNameDefault(blk) : JSON.parse(JSON.stringify(d.def))) }, t("bDefault"))));
    if (d.kind === "multi" || d.kind === "one") {
      const names = d.kind === "multi" ? d.options.concat(v.filter((x) => !d.options.includes(x))) : d.options;
      box.append(h("div", { class: "b-opts" }, names.map((n) => {
        const on = d.kind === "multi" ? v.includes(n) : typeof d.def === "boolean" ? v === true : v === n;
        return h("button", { type: "button", class: "b-opt" + (on ? " on" : ""), "aria-pressed": String(on), onclick: () => {
          if (key === "strategy") return bChange((b) => {
            // the parameters of the strategy being left are kept in memory, so pressing it again brings them back
            const x = b.list[i], old = x.settings.strategy || "leastLoad", stash = bStash[x.id] = bStash[x.id] || {};
            if (old === n) return;
            stash[old] = { load: x.settings.load, probe: x.settings.probe, cost: x.settings.cost };
            x.settings.strategy = n;
            delete x.settings.load; delete x.settings.probe; delete x.settings.cost;
            const back = stash[n] || {};
            ["load", "probe", "cost"].forEach((k) => { if (back[k] !== undefined) x.settings[k] = back[k]; });
            const dp = B_PROBE_DEFAULT[n];
            if (dp && !x.settings.probe) x.settings.probe = Object.assign({}, dp);
          }, true);
          if (d.kind === "one") return typeof d.def === "boolean" ? null : put(n);   // an on/off setting is switched off with the × on its pill
          if (on && v.length === 1) return;
          put(on ? v.filter((x) => x !== n) : v.concat([n]));
        } }, d.options.includes(n) ? bLabel(d, n) : t("bCustom") + ": " + n);
      })));
    }
    if (key === "strategy") box.append(bStrategyFields(blk, v));
    if (key === "member_position") box.append(positionEditor(blk.settings));
    if (key === "member_patch") box.append(memberPatchEditor(blk.settings));
    if (key === "catchall_rules") box.append(catchallEditor(blk.settings));
    if (key === "expand") box.append(expandEditor(blk.settings));
    if (key === "entry_merge") box.append(mergeEditor(blk.settings, "entry_merge", true));
    if (key === "choices") box.append(choicesEditor(blk.settings));
    if (key === "entry") box.append(entryEditor(blk.settings));
    if (key === "endpoints") box.append(endpointsEditor(blk.settings));
    if (key === "patches") box.append(patchesEditor(blk.settings));
    if (d.kind === "list") {
      box.append(h("div", { class: "b-opts" }, v.map((n) => h("button", { type: "button", class: "b-opt mono", onclick: () => { if (v.length > 1) put(v.filter((x) => x !== n)); } }, n, " ×"))));
    }
    if (d.kind === "multi" || d.kind === "list") {
      const inp = h("input", { type: "text", value: bDraft, placeholder: t(d.ph), "aria-label": t(d.add), oninput: (e) => { bDraft = e.target.value; } });
      const add = () => { const x = bDraft.trim(); if (!x || v.includes(x)) return; bDraft = ""; put(v.concat([x])); };
      inp.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); add(); } });
      box.append(h("div", { class: "row" }, inp, h("button", { type: "button", onclick: add }, t(d.add))));
    }
    if (d.kind === "num") {
      box.append(h("div", { class: "row" }, h("input", { type: "number", min: "1", step: "1", value: v, "aria-label": t("s_" + key),
        oninput: (e) => { const n = Math.floor(Number(e.target.value)); if (n >= 1) { blk.settings[key] = n; changed(); } } })));
    }
    if (d.kind === "text") {
      const ex = h("span", { class: "hint" });
      const showEx = (x) => { ex.textContent = t("bExample", { x: x.replace("{block}", blk.name || blk.id).replace("{name}", "Server 1🇩🇪").replace("{country}", "🇩🇪").replace("{n}", "3") }); };
      const inp = h("input", { type: "text", value: v, "aria-label": t("s_name"), oninput: (e) => { blk.settings[key] = e.target.value; showEx(e.target.value); changed(); } });
      showEx(v);
      box.append(h("div", { class: "row" }, inp, ...bTokens(blk).map((tk) => h("button", { type: "button", class: "small mono", onclick: () => put((blk.settings[key] || "") + (/\s$/.test(blk.settings[key] || "") ? "" : " ") + tk) }, tk))), ex);
    }
    return box;
  }
  const PREFIX_BLK = "blk-";
  let bPickSource = false;
  let bBlockDrag = null;
  function bBlockCard(blk, i, all, names, counts) {
    const isBal = blk.type === "balancer";
    const s = blk.settings || {};
    const id = blk.id;
    const nameIn = h("input", { type: "text", class: "b-name", value: blk.name || "", placeholder: prettyId(id), "aria-label": t("bBlockName"),
      oninput: (e) => { blk.name = e.target.value; changed(); } });
    const typeBtn = (k, label) => h("button", { type: "button", class: blk.type === k || (!blk.type && k === "list") ? "on" : "", "aria-pressed": String(blk.type === k),
      onclick: () => bChange((b) => {
        const x = b.list[i];
        if (bType(x) === k) return;
        x.type = k;
        if (k === "list") delete x.per_country; else if (x.per_country === undefined) x.per_country = true;
        if (x.settings) {
          Object.keys(x.settings).forEach((q) => { if (!B_DEF[q] || !bAllowed(B_DEF[q], x)) delete x.settings[q]; });
          if (!Object.keys(x.settings).length) delete x.settings;
        }
        if (k === "warp" && !(x.settings && x.settings.warp)) x.settings = Object.assign({ warp: "exit" }, x.settings || {});
        delete x.advanced;                          // its keys depend on the type
      }) }, label);
    const grip = h("span", { class: "b-grip", draggable: "true", title: t("bDragBlock"), "aria-hidden": "true",
      ondragstart: (e) => { bBlockDrag = i; try { e.dataTransfer.setData("text/plain", "block"); e.dataTransfer.effectAllowed = "move"; } catch (x) { /* ignore */ } },
      ondragend: () => { bBlockDrag = null; } }, "⠿");
    const head = h("div", { class: "b-head" }, grip, nameIn,
      h("div", { class: "seg", role: "group" }, typeBtn("list", t("bList")), typeBtn("balancer", t("bBalancer")), typeBtn("warp", t("bWarp"))),
      isBal || blk.type === "warp" ? h("label", { class: "check small b-pc" }, h("input", { type: "checkbox", checked: !!blk.per_country, onchange: () => bChange((b) => { b.list[i].per_country = !b.list[i].per_country; }) }), t("bPerCountry")) : null,
      h("button", { type: "button", class: "icon", "aria-label": t("bUp"), title: t("bUp"), onclick: () => { const prev = all[all.indexOf(i) - 1]; if (prev !== undefined) bChange((b) => { const x = b.list.splice(i, 1)[0]; b.list.splice(prev, 0, x); }); } }, "↑"),
      h("button", { type: "button", class: "icon", "aria-label": t("bDown"), title: t("bDown"), onclick: () => { const next = all[all.indexOf(i) + 1]; if (next !== undefined) bChange((b) => { const x = b.list.splice(i, 1)[0]; b.list.splice(next, 0, x); }); } }, "↓"),
      h("button", { type: "button", class: "icon danger", "aria-label": t("bDelete"), title: t("bDelete"), onclick: () => bChange((b) => { b.list.splice(i, 1); }) }, "×"));
    const keys = B_SETTINGS.filter((d) => !d.hidden && s[d.key] !== undefined && bAllowed(d, blk)).map((d) => d.key);
    const pills = h("div", { class: "b-pills" }, keys.map((key) => {
      const open = bOpen === id + ":" + key;
      return h("span", { class: "b-pill" + (open ? " open" : "") },
        h("button", { type: "button", "aria-expanded": String(open), onclick: () => { bOpen = open ? null : id + ":" + key; bDraft = ""; drawEditor(); } },
          h("strong", {}, t("s_" + key)), " ", h("span", { class: "dim" }, bSummary(key, s[key])), open ? " ▴" : " ▾"),
        h("button", { type: "button", class: "x", "aria-label": t("remove"), onclick: () => bChange((b) => { delete b.list[i].settings[key]; if (!Object.keys(b.list[i].settings).length) delete b.list[i].settings; }) }, "×"));
    }), blk.advanced ? (() => {
      const open = bOpen === id + ":advanced";
      return h("span", { class: "b-pill adv" + (open ? " open" : "") },
        h("button", { type: "button", "aria-expanded": String(open), onclick: () => { bOpen = open ? null : id + ":advanced"; drawEditor(); } },
          h("strong", {}, t("bAdvancedJson")), " ", h("span", { class: "dim" }, Object.keys(blk.advanced).join(", ") || "—"), open ? " ▴" : " ▾"),
        h("button", { type: "button", class: "x", "aria-label": t("remove"), onclick: () => bChange((b) => { delete b.list[i].advanced; }) }, "×"));
    })() : null, h("button", { type: "button", class: "b-add", "aria-expanded": String(bMenu === id), onclick: () => { bMenu = bMenu === id ? null : id; drawEditor(); } }, t("bAddSetting")));
    const menu = bMenu === id ? (() => {
      const avail = B_SETTINGS.filter((d) => !d.hidden && s[d.key] === undefined && bAllowed(d, blk));
      const items = avail.map((d) => h("button", { type: "button", onclick: () => bChange((b) => {
        const x = b.list[i]; x.settings = x.settings || {}; x.settings[d.key] = d.key === "name" ? bNameDefault(x) : JSON.parse(JSON.stringify(d.def));
      }, true) }, t("s_" + d.key)));
      if (!blk.advanced) items.push(h("button", { type: "button", onclick: () => { bChange((b) => { b.list[i].advanced = {}; }, true); bOpen = id + ":advanced"; bMenu = null; drawEditor(); } }, t("bAdvancedJson")));
      return h("div", { class: "b-menu" }, items.length ? items : h("span", { class: "hint" }, t("bAllSettings")));
    })() : null;
    const openKey = keys.find((key) => bOpen === id + ":" + key);
    let extraEditor = null;
    if (bOpen === id + ":advanced" && blk.advanced) {
      const ta = h("textarea", { rows: 10, spellcheck: "false" });
      ta.value = JSON.stringify(blk.advanced, null, 2);
      ta.addEventListener("input", () => {
        let v;
        try { v = ta.value.trim() ? JSON.parse(ta.value) : {}; } catch (e) { ta.classList.add("bad"); return; }
        if (!isObj(v)) { ta.classList.add("bad"); return; }
        ta.classList.remove("bad");
        blk.advanced = v; changed();
      });
      ta.addEventListener("change", () => drawEditor());
      const movable = bType(blk) !== "drop" && (bMovable(blk).length || (bType(blk) === "list" && Array.isArray(blk.advanced.patches) && !((blk.settings || {}).patches || []).length) || (Array.isArray(blk.advanced.member_patch) && !((blk.settings || {}).member_patch || []).length));
      extraEditor = h("div", { class: "b-editor" }, h("div", { class: "row" }, h("strong", {}, t("bAdvancedJson")),
        h("span", { class: "hint", style: "flex:1" }, t(B_ADV_HINT[bType(blk)] || "bAdvList"))),
        movable ? h("div", { class: "row" }, h("button", { type: "button", class: "small", onclick: () => bMoveAdvanced(i) }, t("bMoveAdv")),
          h("span", { class: "hint" }, t("bMoveAdvHint"))) : null, ta);
    }
    const kindOpen = (blk.kinds || []).findIndex((w, j) => bOpen === id + ":kind:" + j);
    if (kindOpen >= 0) {
      const j = kindOpen;
      const cur = () => cfg.blocks.list[i].kinds[j];
      const holder = new Proxy({}, {
        get: (o, k) => (k === "when" ? condOnly(cur()) : undefined),
        set: (o, k, v) => { if (k === "when") cfg.blocks.list[i].kinds[j] = Object.assign({}, v || {}); return true; },
        deleteProperty: (o, k) => { if (k === "when") cfg.blocks.list[i].kinds[j] = {}; return true; },
        has: (o, k) => k === "when",
      });
      extraEditor = h("div", { class: "b-editor" }, h("div", { class: "row" }, h("strong", { style: "flex:1" }, t("bEditCond")),
        h("button", { type: "button", class: "small", onclick: () => { bOpen = null; drawEditor(); } }, t("bDone"))), whenEditor(holder));
    }
    if (bOpen === id + ":newcond") {
      const holder = bNewCond[id] = bNewCond[id] || {};
      extraEditor = h("div", { class: "b-editor" }, h("div", { class: "row" }, h("strong", { style: "flex:1" }, t("bNewCond"))),
        whenEditor(holder), h("div", { class: "row" },
          h("button", { type: "button", class: "primary", onclick: () => {
            const w = holder.when;
            if (!w || !Object.keys(condOnly(w)).length) return;
            delete bNewCond[id]; bOpen = null;
            bChange((b) => { b.list[i].kinds = (b.list[i].kinds || []).concat([JSON.parse(JSON.stringify(w))]); });
          } }, t("bAddCond")),
          h("button", { type: "button", onclick: () => { delete bNewCond[id]; bOpen = null; drawEditor(); } }, t("cancel"))));
    }
    const zone = bZone(i, h("div", { class: "b-zone" },
      (blk.kinds || []).map((w, j) => bChip(w, names, () => bMove(w, "rest"), t("bTakeOut"), "", false,
        () => { bOpen = bOpen === id + ":kind:" + j ? null : id + ":kind:" + j; drawEditor(); })),
      (blk.kinds || []).length ? null : h("span", { class: "hint" }, t("bDropHere")),
      h("button", { type: "button", class: "b-cond", onclick: () => { bOpen = id + ":newcond"; drawEditor(); } }, t("bPlusCond")),
      bHasPick() ? h("button", { type: "button", class: "b-movehere", onclick: () => bMove(bPicked(), i, bSel.length ? true : bPickSource) }, t("bMoveHere")) : null));
    // list blocks leave no trace in the preview report: count the sample configs of their kinds instead
    const n = counts[PREFIX_BLK + id] || (bType(blk) === "list" ? (blk.kinds || []).reduce((sum, w) => sum + ((names[kkey(w)] || {}).count || 0), 0) : 0);
    const card = h("div", { class: "b-block" + (blk.type === "warp" ? " warp" : "") }, head, h("p", { class: "hint b-takes" }, sample ? t("bTakes", { n }) : ""),
      pills, menu, openKey ? bSettingEditor(blk, i, openKey) : extraEditor, zone);
    // blocks move by dragging their grip onto another block (it goes before or after, by where it is dropped)
    card.addEventListener("dragover", (e) => {
      if (bBlockDrag === null || bBlockDrag === i) return;
      e.preventDefault();
      const r = card.getBoundingClientRect(), after = e.clientY > r.top + r.height / 2;
      card.classList.toggle("drop-before", !after); card.classList.toggle("drop-after", after);
    });
    card.addEventListener("dragleave", (e) => { if (!card.contains(e.relatedTarget)) card.classList.remove("drop-before", "drop-after"); });
    card.addEventListener("drop", (e) => {
      if (bBlockDrag === null) return;
      e.preventDefault(); e.stopPropagation();
      const from = bBlockDrag, after = card.classList.contains("drop-after");
      card.classList.remove("drop-before", "drop-after");
      bBlockDrag = null;
      if (from === i) return;
      bChange((b) => {
        const x = b.list.splice(from, 1)[0];
        let to = b.list.findIndex((y) => y.id === blk.id);
        if (after) to += 1;
        b.list.splice(to, 0, x);
      });
    });
    return card;
  }
  function bChip(w, names, onX, xLabel, cls, fromSource, onEdit) {
    const info = names[kkey(w)];
    const text = w._label || (info && info.label) || describeWhen(condOnly(w)) || t("bOtherCond");
    return h("span", Object.assign({ class: "b-chip " + (cls || "") }, bDragProps(w, fromSource)),
      onEdit ? h("button", { type: "button", class: "b-chip-edit", title: t("bEditCond"), onclick: onEdit }, text) : h("span", {}, text),
      info ? h("span", { class: "dim" }, "×" + info.count) : null,
      onX ? h("button", { type: "button", class: "x", "aria-label": xLabel, title: xLabel, onclick: onX }, cls === "gone" ? t("bBringBack") : "×") : null);
  }
  function blocksView() {
    bLoadKinds();
    const v = bView();
    const names = {};
    (bKinds || []).forEach((k) => { names[kkey(k.when)] = { label: (k.flag ? k.flag + " " : "") + k.label, count: k.count }; });
    const place = {};
    v.list.forEach((b, i) => (b.kinds || []).forEach((w) => { const key = kkey(w); if (!(key in place)) place[key] = i; }));
    // what really happens to each sample config, from the last preview: block or classic item ids
    const rep = lastPreview && lastPreview.report && Array.isArray(lastPreview.report.configs) && sample && lastPreview.report.configs.length === sample.length ? lastPreview.report.configs : null;
    const usedBy = (c) => {
      const ids = [];
      if (c.rule && (c.action === "drop" || c.action === "pin_top" || c.action === "pin_bottom" || !c.rule.startsWith("blk-"))) ids.push(c.rule);
      (c.groups || []).forEach((g) => ids.push(g.replace(/--noflag$/, "")));
      (c.chains || []).forEach((x) => ids.push(x));
      return ids;
    };
    const counts = {}, kindIds = {};
    if (rep) rep.forEach((c) => usedBy(c).forEach((id) => { counts[id] = (counts[id] || 0) + 1; }));
    (bKinds || []).forEach((k) => {
      const ids = [];
      (k.indexes || []).forEach((n) => { if (rep && rep[n]) usedBy(rep[n]).forEach((id) => { if (!ids.includes(id)) ids.push(id); }); });
      kindIds[kkey(k.when)] = ids;
    });
    const where = (key) => {
      const ids = kindIds[key];
      if (ids && ids.length) return t("bIn", { b: ids.map(idName).join(", ") });
      const i = place[key];
      if (i === undefined) return t("bNotPlaced");
      const b = v.list[i];
      return b.type === "drop" ? t("bRemovedWhere") : t("bIn", { b: b.name || prettyId(b.id) });
    };
    const isPlaced = (key) => key in place || (kindIds[key] || []).length > 0;

    const toolbar = h("div", { class: "row b-tools" },
      h("button", { type: "button", "aria-expanded": String(bTestOpen), onclick: () => { bTestOpen = !bTestOpen; drawEditor(); } }, t("bTestUsers")),
      h("button", { type: "button", disabled: !bPast.length, onclick: () => { bFuture.unshift(bSnap()); bRestore(bPast.pop()); } }, t("bUndo")),
      h("button", { type: "button", disabled: !bFuture.length, onclick: () => { bPast.push(bSnap()); bRestore(bFuture.shift()); } }, t("bRedo")));

    let source;
    if (!bKinds) source = h("p", { class: "hint" }, t("bNoSample"));
    else {
      const total = bKinds.reduce((a, k) => a + k.count, 0);
      source = h("div", {},
        h("p", { class: "hint" }, t("bKindsN", { n: total, k: bKinds.length })),
        bSel.length ? h("p", { class: "hint" }, t("bSelN", { n: bSel.length }) + " ", h("button", { type: "button", class: "small", onclick: () => { bSel = []; bSelLast = -1; drawEditor(); } }, t("bSelClear"))) : h("p", { class: "hint" }, t("bSelHint")),
        h("div", { class: "b-kinds" }, bKinds.map((k, n) => {
          const cond = bCond(k), key = kkey(k.when), picked = bPick && kkey(bPick) === key, sel = bSel.includes(key);
          const props = bDragProps(cond, true);
          const startDrag = props.ondragstart;
          props.ondragstart = (e) => {                      // dragging one of several selected kinds drags them all
            startDrag(e);
            if (sel && bSel.length > 1) bDrag = bKinds.filter((x) => bSel.includes(kkey(x.when))).map(bCond);
          };
          return h("div", Object.assign({ class: "b-kind" + (isPlaced(key) ? " placed" : "") + (picked ? " picked" : "") + (sel ? " selected" : ""),
            onclick: (e) => {
              if (e.target.closest("button")) return;
              if (e.shiftKey && bSelLast >= 0) {
                const [a, z] = [Math.min(bSelLast, n), Math.max(bSelLast, n)];
                bSel = bKinds.slice(a, z + 1).map((x) => kkey(x.when));
              } else if (e.ctrlKey || e.metaKey) {
                bSel = sel ? bSel.filter((x) => x !== key) : bSel.concat([key]); bSelLast = n;
              } else { bSel = sel && bSel.length === 1 ? [] : [key]; bSelLast = n; }
              bPick = null; drawEditor();
            } }, props),
            h("span", { class: "b-cc" }, k.flag || "·"),
            h("div", { class: "b-kind-text" }, h("div", { class: "b-kind-label", title: k.remarks.join("\n") }, k.label), h("div", { class: "hint" }, k.count + " · " + where(key))),
            h("button", { type: "button", class: "small" + (picked ? " primary" : ""), "aria-pressed": String(!!picked), onclick: () => { bPick = picked ? null : cond; bPickSource = true; bSel = []; drawEditor(); } }, picked ? t("bPicked") : t("bPick")));
        })));
    }

    const order = v.list.map((b, i) => i).filter((i) => v.list[i].type !== "drop");
    const blocks = order.map((i) => bBlockCard(v.list[i], i, order, names, counts));
    const nb = (type) => bChange((b) => {
      const n = b.list.filter((x) => x.type !== "drop").length + 1;
      const item = { id: nextId("block", b.list), name: t(type === "balancer" ? "bNewBalancer" : type === "warp" ? "bNewWarp" : "bNewBlock", { n }), type, kinds: [] };
      if (type === "balancer") { item.per_country = true; item.settings = { strategy: "leastLoad" }; }
      if (type === "warp") { item.per_country = true; item.settings = { warp: "exit" }; }
      const firstDrop = b.list.findIndex((x) => x.type === "drop");
      if (firstDrop < 0) b.list.push(item); else b.list.splice(firstDrop, 0, item);
    });
    const restKinds = (bKinds || []).filter((k) => !isPlaced(kkey(k.when)));
    const seg = (val, label) => h("button", { type: "button", class: (v.rest || "keep") === val ? "on" : "", "aria-pressed": String((v.rest || "keep") === val), onclick: () => bChange((b) => { b.rest = val; }) }, label);
    const rest = bZone("rest", h("div", { class: "b-block b-rest" + ((v.rest || "keep") === "hide" ? " hidden-rest" : "") },
      h("div", { class: "b-head" }, h("strong", { style: "flex:1" }, t("bRest")), h("div", { class: "seg", role: "group" }, seg("top", t("bKeepTop")), seg("keep", t("bKeepEnd")), seg("hide", t("bHide")))),
      h("p", { class: "hint" }, t("bRestHint")),
      h("div", { class: "b-zone plain" }, restKinds.map((k) => bChip(bCond(k), names, null, null, "", true)), restKinds.length || !bKinds ? null : h("span", { class: "hint" }, t("bRestEmpty")))));
    const gone = [];
    v.list.forEach((b) => { if (b.type === "drop") (b.kinds || []).forEach((w) => gone.push(w)); });
    const trash = bZone("trash", h("div", { class: "b-block b-trash" },
      h("div", { class: "b-head" }, h("strong", { class: "danger-text" }, "🗑 " + t("bRemoved")), h("span", { class: "hint", style: "flex:1" }, t("bRemovedHint")),
        bHasPick() ? h("button", { type: "button", class: "danger", onclick: () => bMove(bPicked(), "trash", bSel.length ? true : bPickSource) }, t("bRemove")) : null),
      gone.length ? h("div", { class: "b-zone plain" }, gone.map((w) => bChip(w, names, () => bMove(w, "rest"), t("bBringBack"), "gone"))) : null));

    // the items made in the old tabs, shown as locked blocks with the kinds they take
    const classic = [];
    const kindsOf = (id) => (bKinds || []).filter((k) => (kindIds[kkey(k.when)] || []).includes(id));
    (cfg.groups || []).forEach((g, gi) => { if (g.enabled !== false) classic.push({ id: g.id, kind: "group", label: t("bOldBalancer"), convert: () => bConvertGroup(gi), open: "groups" }); });
    (cfg.rules || []).forEach((r, ri) => { if (r.enabled !== false) classic.push({ id: r.id, kind: "rule", label: r.do === "drop" ? t("bOldDrop") : t("bOldRule"), convert: r.do === "drop" ? () => bConvertRule(ri) : null, open: "list" }); });
    (cfg.chains || []).forEach((c, ci) => { if (c.enabled !== false) classic.push({ id: c.id, kind: "chain", label: t("bOldWarp"), convert: c.mode === "exit_first" ? () => bConvertChain(ci) : null, open: "chains" }); });
    const offOld = ["groups", "rules", "chains"].reduce((n, k) => n + (cfg[k] || []).filter((x) => x.enabled === false).length, 0);
    const cleanBtn = offOld ? h("button", { type: "button", class: "small", onclick: () => bChange(() => {
      ["groups", "rules", "chains"].forEach((k) => { if (Array.isArray(cfg[k])) cfg[k] = cfg[k].filter((x) => x.enabled !== false); });
    }) }, t("bCleanOld", { n: offOld })) : null;
    const classicBox = classic.length || offOld ? h("div", { class: "b-classic" },
      h("div", { class: "row" }, h("h3", { style: "flex:1" }, t("bClassicTitle")), cleanBtn),
      classic.length ? h("p", { class: "hint" }, t("bClassicHint")) : null,
      classic.map((it) => {
        const ks = kindsOf(it.id);
        return h("div", { class: "b-block locked" },
          h("div", { class: "b-head" }, h("span", { class: "b-lock", "aria-hidden": "true" }, "🔒"), h("strong", { style: "flex:1" }, prettyId(it.id)), h("span", { class: "chip" }, it.label),
            it.convert ? h("button", { type: "button", class: "primary small", onclick: it.convert }, t("bConvert")) : null,
            h("button", { type: "button", class: "small", onclick: () => { tab = "advanced"; advTab = it.open; drawEditor(); } }, t("bOpenOld"))),
          h("div", { class: "b-zone plain" }, ks.length ? ks.map((k) => h("span", { class: "b-chip" }, (k.flag ? k.flag + " " : "") + k.label, h("span", { class: "dim" }, "×" + k.count)))
            : h("span", { class: "hint" }, sample ? t("bTakesNothing") : t("bNoSampleShort"))));
      })) : null;

    const testBox = bTestOpen ? bTestView() : null;
    return h("div", { class: "builder" },
      h("section", { class: "b-source" }, h("h2", {}, t("bFromPanel")), h("p", { class: "hint" }, t("bSourceHint")), source),
      h("section", { class: "b-final" },
        h("div", { class: "row" }, h("h2", { style: "flex:1;margin:0" }, t("bFinal")), toolbar),
        h("p", { class: "hint" }, t("bFinalHint")),
        testBox,
        classicBox,
        ...blocks,
        h("div", { class: "row" }, h("button", { type: "button", class: "b-new", onclick: () => nb("list") }, t("bAddList")), h("button", { type: "button", class: "b-new", onclick: () => nb("balancer") }, t("bAddBalancer")),
          h("button", { type: "button", class: "b-new", onclick: () => nb("warp") }, t("bAddWarp"))),
        rest, trash));
  }


  // turn a classic group / drop rule into a block; the classic item is switched off (not deleted)
  const B_FRAG_PATH = "streamSettings.finalmask.tcp", B_CS_PATH = "streamSettings.tlsSettings.cipherSuites";
  const presetName = (v, known) => Object.keys(known).find((k) => canon(known[k]) === canon(v));
  const B_ADV_GROUP = ["params", "probe", "member_cost"];
  function bConvertGroup(gi) {
    const g = cfg.groups[gi];
    bChange((b) => {
      const settings = {}, advGroup = {}, rest = [];
      if (["leastLoad", "leastPing", "random", "roundRobin"].includes(g.type)) settings.strategy = g.type;
      const perCountry = !!(g.split_by && g.split_by.field === "flag" && g.split_by.regex === "(.+)");
      if (g.split_by && !perCountry) advGroup.split_by = JSON.parse(JSON.stringify(g.split_by));
      const name = g.name || (g.split_by ? "{split}" : g.id);
      if (perCountry) settings.name = name.replace(/\{split\}/g, "{country}").replace(/\{group\}/g, "{block}");
      else advGroup.name = name;
      B_ADV_GROUP.forEach((k) => { if (g[k] !== undefined) advGroup[k] = JSON.parse(JSON.stringify(g[k])); });
      ["member_position", "catchall_rules", "expand", "min_members", "position", "include_balanced", "probe_kind"].forEach((k) => { if (g[k] !== undefined) settings[k] = JSON.parse(JSON.stringify(g[k])); });
      if (g.remove_members_from_output === false) settings.keep_members = true;
      (g.member_patch || []).forEach((step) => {
        const st = JSON.parse(JSON.stringify(step));
        if (!st.when && isObj(st.random)) {
          const fr = st.random[B_FRAG_PATH];
          if (Array.isArray(fr) && fr.length && fr.every((x) => Array.isArray(x) && x.length && x.every(isObj))) {
            settings.fragment = fr.map((x) => presetName(x, FRAG_PRESETS) || x); delete st.random[B_FRAG_PATH];
          }
          const cs = st.random[B_CS_PATH];
          if (Array.isArray(cs) && cs.length && cs.every((x) => typeof x === "string" && /^[A-Z0-9_:]+$/.test(x))) {
            settings.cipher = cs.map((x) => presetName(x, CS_PRESETS) || x); delete st.random[B_CS_PATH];
          }
          if (!Object.keys(st.random).length) delete st.random;
        }
        if (Object.keys(st).some((k) => k !== "when")) rest.push(st);
      });
      const block = { id: nextId("block", b.list), name: prettyId(g.id), type: "balancer",
        kinds: [Object.assign({ _label: t("bOldCond", { id: prettyId(g.id) }) }, g.when || {})] };
      if (perCountry) { block.per_country = true; block.flagless = "single"; }      // as the old group did
      if (Object.keys(settings).length) block.settings = settings;
      const adv = {};
      if (Object.keys(advGroup).length) adv.group = advGroup;
      if (rest.length) { block.settings = block.settings || {}; block.settings.member_patch = rest; }
      if (Object.keys(adv).length) block.advanced = adv;
      const firstOther = b.list.findIndex((x) => x.type !== "balancer");
      if (firstOther < 0) b.list.push(block); else b.list.splice(firstOther, 0, block);
      cfg.groups[gi].enabled = false;
    });
  }
  const B_ADV_CHAIN = ["exit", "before"];
  function bConvertChain(ci) {
    const c = cfg.chains[ci];
    bChange((b) => {
      const settings = {}, adv = {};
      const perCountry = !!(c.split_by && c.split_by.field === "flag" && c.split_by.regex === "(.+)");
      if (c.split_by && !perCountry) adv.split_by = JSON.parse(JSON.stringify(c.split_by));
      if (c.exit === false) settings.warp = "only"; else settings.warp = "exit";
      if (c.pick === "per_user") settings.pick = "per_user";
      const name = c.name || (c.split_by ? "{split}" : c.id);
      if (perCountry || !c.split_by) settings.name = name.replace(/\{split\}/g, "{country}").replace(/\{group\}/g, "{block}");
      else adv.name = name;
      if (c.entry !== "{account.masque.outbound}") settings.entry = JSON.parse(JSON.stringify(c.entry));
      if (c.endpoints !== "{account.masque.endpoints}" && c.endpoints !== undefined) {
        const ok = typeof c.endpoints === "string" || (Array.isArray(c.endpoints) && c.endpoints.every((x) => typeof x === "string"));
        if (ok) settings.endpoints = JSON.parse(JSON.stringify(c.endpoints)); else adv.endpoints = JSON.parse(JSON.stringify(c.endpoints));
      }
      if (isObj(c.choices)) settings.choices = JSON.parse(JSON.stringify(c.choices));
      B_ADV_CHAIN.forEach((k) => { if (c[k] !== undefined && !(k === "exit" && c[k] === false)) adv[k] = JSON.parse(JSON.stringify(c[k])); });
      if (c.position) settings.position = c.position;
      if (c.remove_exit_from_output === true) settings.remove_exit = true;
      if (isObj(c.entry_merge)) settings.entry_merge = JSON.parse(JSON.stringify(c.entry_merge));
      const block = { id: nextId("block", b.list), name: prettyId(c.id), type: "warp",
        kinds: [Object.assign({ _label: t("bOldCond", { id: prettyId(c.id) }) }, c.exit_when || {})], settings };
      if (perCountry) block.per_country = true;
      // an old decoy in front of a WARP-only entry becomes the block's own Decoy setting, not a hidden advanced key
      if (Array.isArray(adv.before) && adv.before.length === 1 && adv.before[0] && adv.before[0].tag === "decoy" && adv.before[0].protocol === "vless") {
        settings.decoy = "vless"; delete adv.before;
      }
      if (Object.keys(adv).length) block.advanced = { chain: adv };
      const firstDrop = b.list.findIndex((x) => x.type === "drop");
      if (firstDrop < 0) b.list.push(block); else b.list.splice(firstDrop, 0, block);
      cfg.chains[ci].enabled = false;
    });
  }
  function bConvertRule(ri) {
    const r = cfg.rules[ri];
    bChange((b) => {
      let i = b.list.findIndex((x) => x.type === "drop");
      if (i < 0) { b.list.push({ id: nextId("removed", b.list), type: "drop", kinds: [] }); i = b.list.length - 1; }
      b.list[i].kinds = (b.list[i].kinds || []).concat([Object.assign({ _label: t("bOldCond", { id: prettyId(r.id) }) }, r.when || {})]);
      cfg.rules[ri].enabled = false;
    });
  }
  // ---------- output tab ----------
  const OUT_DEFAULTS = {
    dedicated_dns: () => ({ ip: "8.8.8.8", tag: "dedicated-dns" }),
    direct_dns: () => ({ tag_regex: "^domestic-dns" }),
    panel_balancers: () => ({ max_rtt: "2500ms", few_max_members: 2, expected_few: 1, expected_many: 2 }),
  };
  function optSection(obj, key, labelKey, bodyFn) {
    const box = h("div", { class: "opt" });
    function draw() {
      box.replaceChildren();
      const v = obj[key];
      const on = v !== undefined && v !== false && v !== null;
      const cb = h("input", { type: "checkbox", checked: on, onchange: () => {
        if (cb.checked) obj[key] = OUT_DEFAULTS[key](); else delete obj[key];
        changed(); draw();
      } });
      box.append(h("label", { class: "check" }, cb, t(labelKey)));
      if (!on) return;
      if (v === true) {
        box.append(h("p", { class: "hint" }, t("usingDefaults") + " ",
          h("button", { type: "button", onclick: () => { obj[key] = OUT_DEFAULTS[key](); changed(); draw(); } }, t("customize"))));
        return;
      }
      if (v && typeof v === "object") box.append(bodyFn(v));
    }
    draw();
    return box;
  }
  const flag = (o, key, labelKey) => h("div", { class: "row" }, h("label", { class: "check" }, bindBool(o, key, false), t(labelKey)));

  function baseRulesEditor(o) {
    const box = h("div", { class: "opt" });
    const mode = () => (Array.isArray(o.base_rules) ? "custom" : o.base_rules ? "builtin" : "off");
    function draw() {
      box.replaceChildren();
      const s = h("select", { onchange: () => {
        if (s.value === "off") delete o.base_rules; else if (s.value === "builtin") o.base_rules = true; else o.base_rules = JSON.parse(JSON.stringify(directRules));
        changed(); draw();
      } }, [["off", t("baseOff")], ["builtin", t("baseBuiltin")], ["custom", t("baseCustom")]].map(([v, l]) => h("option", { value: v }, l)));
      s.value = mode();
      box.append(field(t("baseRules"), s, t("baseRulesHint"), true));
      if (mode() === "builtin") box.append(h("pre", { class: "hint" }, JSON.stringify(directRules, null, 2)));
      if (mode() === "custom") box.append(field(t("baseRulesList"), bindJSON(o, "base_rules", 6), null, true));
    }
    draw();
    return box;
  }

  function samplingEditor(o) {
    const box = h("div", { class: "opt" });
    const mode = () => (o.sampling && o.sampling.fixed ? "fixed" : o.sampling && o.sampling.members_div ? "div" : "off");
    function draw() {
      box.replaceChildren();
      const s = h("select", { onchange: () => {
        if (s.value === "off") delete o.sampling; else if (s.value === "fixed") o.sampling = { fixed: 2 }; else o.sampling = { members_div: 2, extra: 0 };
        changed(); draw();
      } }, [["off", t("samplingOff")], ["fixed", t("samplingFixed")], ["div", t("samplingDiv")]].map(([v, l]) => h("option", { value: v }, l)));
      s.value = mode();
      box.append(field(t("samplingTitle"), s, null, true));
      if (mode() === "fixed") box.append(field(t("samplingFixedN"), bindText(o.sampling, "fixed", { num: true, optional: false })));
      if (mode() === "div") box.append(h("div", { class: "grid" },
        field(t("samplingDivN"), bindText(o.sampling, "members_div", { num: true, optional: false })),
        field(t("samplingExtra"), bindText(o.sampling, "extra", { num: true }))));
    }
    draw();
    return box;
  }

  function remarkRewriteEditor(o) {
    const box = h("div", { class: "opt" });
    function draw() {
      box.replaceChildren(h("h4", {}, t("remarkTitle")), h("p", { class: "hint" }, t("remarkHint")));
      const list = (o.remark_rewrite = Array.isArray(o.remark_rewrite) ? o.remark_rewrite : []);
      list.forEach((e, i) => {
        box.append(h("div", { class: "item" },
          h("div", { class: "grid" },
            field(t("rwRegex"), bindText(e, "regex")),
            field(t("rwReplace"), bindText(e, "replace")),
            field(t("rwIf"), bindText(e, "if"))),
          h("div", { class: "row" },
            h("button", { type: "button", onclick: () => { if (i > 0) { [list[i - 1], list[i]] = [list[i], list[i - 1]]; changed(); draw(); } } }, "↑"),
            h("button", { type: "button", onclick: () => { if (i < list.length - 1) { [list[i + 1], list[i]] = [list[i], list[i + 1]]; changed(); draw(); } } }, "↓"),
            h("button", { type: "button", class: "danger", onclick: () => { list.splice(i, 1); if (!list.length) delete o.remark_rewrite; changed(); draw(); } }, t("remove")))));
      });
      box.append(h("button", { type: "button", onclick: () => { list.push({ regex: "", replace: "" }); o.remark_rewrite = list; changed(); draw(); } }, t("addRule")));
      if (!list.length) delete o.remark_rewrite;
    }
    draw();
    return box;
  }

  let quicDefaults = [];
  let directRules = [];
  let sniffDefaults = { destOverride: ["http", "tls", "quic", "fakedns"], routeOnly: false };
  function quicEditor(o, quic) {
    const wrap = h("div", {});
    let was = null;
    function draw() {
      const own = quic.length > 0;
      was = own;
      wrap.replaceChildren(
        chipsInput(quic, () => { if (quic.length) o.quic_domains = quic; else delete o.quic_domains; changed(); if ((quic.length > 0) !== was) draw(); }, "youtube.com"),
        ...(own ? [] : [h("div", { class: "hint" }, quicDefaults.join(", ")),
          h("button", { type: "button", onclick: () => { quic.push(...quicDefaults); o.quic_domains = quic; changed(); draw(); } }, t("quicEdit"))]));
    }
    draw();
    return wrap;
  }

  // the socks/http inbounds built by "split_inbounds": what is built by default is shown, and only a change is saved
  function splitFlagAndOptions(o) {
    const box = h("div", {});
    const draw = () => box.replaceChildren(
      h("div", { class: "row" }, h("label", { class: "check" }, (() => {
        const c = bindBool(o, "split_inbounds", false);
        c.addEventListener("change", draw);
        return c;
      })(), t("splitInbounds"))),
      ...(o.split_inbounds ? [splitInboundsEditor(o)] : []));
    draw();
    return box;
  }
  function splitInboundsEditor(o) {
    const over = Array.isArray(o.sniff_override) ? o.sniff_override.slice() : sniffDefaults.destOverride.slice();
    const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
    return h("div", { class: "opt" },
      field(t("sniffOver"), chipsInput(over, () => { if (same(over, sniffDefaults.destOverride)) delete o.sniff_override; else o.sniff_override = over.slice(); changed(); }, "tls"), t("sniffHint"), true),
      h("div", { class: "row" }, h("label", { class: "check" }, (() => {
        const c = h("input", { type: "checkbox" }); c.checked = o.route_only === undefined ? !!sniffDefaults.routeOnly : !!o.route_only;
        c.addEventListener("change", () => { if (c.checked === !!sniffDefaults.routeOnly) delete o.route_only; else o.route_only = c.checked; changed(); });
        return c;
      })(), t("routeOnly"))),
      h("div", { class: "grid" }, field(t("socksPort"), bindText(o, "socks_port", { num: true })), field(t("httpPort"), bindText(o, "http_port", { num: true }))));
  }

  function outputEditor() {
    const o = (cfg.output = cfg.output && typeof cfg.output === "object" && !Array.isArray(cfg.output) ? cfg.output : {});
    const quic = Array.isArray(o.quic_domains) ? o.quic_domains : [];
    const dom = h("select", { onchange: () => { if (dom.value) o.domain_strategy = dom.value; else delete o.domain_strategy; changed(); } },
      [["", "—"], ["AsIs", "AsIs"], ["IPIfNonMatch", "IPIfNonMatch"], ["IPOnDemand", "IPOnDemand"]].map(([v, l]) => h("option", { value: v }, l)));
    dom.value = o.domain_strategy || "";
    return h("div", {},
      h("p", { class: "hint" }, t("outHint")),
      h("div", { class: "row" }, h("label", { class: "check" }, bindBool(o, "enabled", true), t("outEnabled"))),
      whenEditor(o, "when", "outWhen"),
      detailsBox("sectInbounds", h("div", {},
        splitFlagAndOptions(o),
        flag(o, "dns_out", "dnsOut"),
        flag(o, "block_udp_443", "blockUdp"),
        h("label", { class: "f wide" }, t("quicDomains"),
          quicEditor(o, quic)),
        flag(o, "replace_routing", "replaceRouting"),
        field(t("domainStrategy"), dom),
        baseRulesEditor(o)), true),
      detailsBox("sectDns", h("div", {},
        optSection(o, "dedicated_dns", "dedicatedDns", (v) => h("div", { class: "grid" },
          field(t("ddIp"), bindText(v, "ip")), field(t("ddTag"), bindText(v, "tag")))),
        optSection(o, "direct_dns", "directDns", (v) => h("div", { class: "grid" }, field(t("ddRegex"), bindText(v, "tag_regex")))))),
      detailsBox("sectTuning", h("div", {},
        samplingEditor(o),
        optSection(o, "panel_balancers", "panelBal", (v) => h("div", { class: "grid" },
          field(t("pbRtt"), bindText(v, "max_rtt")),
          field(t("pbFew"), bindText(v, "few_max_members", { num: true })),
          field(t("pbExpFew"), bindText(v, "expected_few", { num: true })),
          field(t("pbExpMany"), bindText(v, "expected_many", { num: true })))))),
      detailsBox("sectRemark", remarkRewriteEditor(o)));
  }

  const orderBody = (r) => h("div", {}, whenEditor(r),
    h("div", { class: "row" }, field(t("rank"), bindText(r, "rank", { num: true, optional: false }), t("rankHint"))));


  const TEMPLATES = {
    rules: [
      ["tpl_rule_name", (items) => ({ id: nextId("rule", items), when: { remark: { contains: "" } }, do: "drop" })],
      ["tpl_rule_proto", (items) => ({ id: nextId("rule", items), when: { protocol: "" }, do: "drop" })],
      ["tpl_rule_top", (items) => ({ id: nextId("rule", items), when: { remark: { contains: "" } }, do: "pin_top" })],
      ["tpl_blank", (items) => ({ id: nextId("rule", items), when: {}, do: "drop" })],
    ],
    groups: [
      ["tpl_group_flag", (items) => ({ id: nextId("group", items), type: "leastLoad", when: { remark: { contains: "" } }, split_by: { field: "flag", regex: "(.+)" }, name: "{split} Auto" })],
      ["tpl_group_all", (items) => ({ id: nextId("group", items), type: "leastLoad", when: { remark: { contains: "" } }, name: "Auto" })],
      ["tpl_blank", (items) => ({ id: nextId("group", items), type: "leastLoad", when: {} })],
    ],
    chains: [
      ["tpl_chain_warp", (items) => ({ id: nextId("chain", items), mode: "exit_first", exit_when: { remark: { contains: "" } }, entry: "{account.masque.outbound}", endpoints: "{account.masque.endpoints}", pick: "random" })],
      ["tpl_blank", (items) => ({ id: nextId("chain", items), exit_when: {}, entry: {} })],
    ],
    order: [
      ["tpl_order_name", (items) => ({ id: nextId("order", items), when: { remark: { contains: "" } }, rank: 0 })],
      ["tpl_blank", (items) => ({ id: nextId("order", items), rank: 30 })],
    ],
  };
  const sect = (titleKey, ...kids) => h("div", { class: "sect-plain" }, h("h2", {}, t(titleKey)), ...kids);
  let advTab = "list";
  function drawEditor() {
    if (tab === "rules" || tab === "order") { tab = "advanced"; advTab = "list"; }
    if (tab === "list" || tab === "groups" || tab === "chains") { advTab = tab; tab = "advanced"; }
    if (tab === "patches" || tab === "raw") { advTab = tab === "raw" ? "raw" : "patches"; tab = "advanced"; }
    if (tab === "output") tab = "settings";
    const proxyOnly = (cfg.panel || {}).mode === "proxy";
    // a plain reverse proxy has no rules: only the setup guide, the settings and the raw JSON stay
    const tabs = proxyOnly ? [["start", t("start")], ["settings", t("tabSettings")], ["advanced", t("tabAdvanced")]]
      : [["start", t("start")], ["blocks", t("tabBlocks")], ["settings", t("tabSettings")], ["advanced", t("tabAdvanced")]];
    if (proxyOnly && tab === "blocks") tab = "start";
    if (proxyOnly && tab === "advanced") advTab = "raw";
    let body;
    const mainEl = document.querySelector("main");
    if (mainEl) mainEl.classList.toggle("wide", tab === "blocks");
    if (tab === "start") body = wizardView();
    else if (tab === "blocks") body = blocksView();
    else if (tab === "settings") body = h("div", {}, settingsEditor(), proxyOnly ? null : detailsBox("sectOutput", outputEditor()), h("p", { class: "hint" }, t("adminNote")));
    else {
      // the old tabs show only while they hold something (made there, or switched off after Convert to block)
      const has = (k) => Array.isArray(cfg[k]) && cfg[k].length > 0;
      const oldTabs = [["list", t("advRules"), has("rules") || has("order")], ["groups", t("tabGroups"), has("groups")], ["chains", t("tabWarp"), has("chains")], ["patches", t("advPatches"), has("patches")]];
      const subs = proxyOnly ? [["raw", t("advJson")], ["profile", t("profile")]] : [...oldTabs.filter((x) => x[2]).map((x) => [x[0], x[1]]), ["raw", t("advJson")], ["profile", t("profile")]];
      if (!subs.some((x) => x[0] === advTab)) advTab = subs[0][0];
      let inner;
      if (advTab === "groups") inner = listEditor("groups", "groupsHint", (items) => ({ id: nextId("group", items), type: "leastLoad", when: {} }), groupBody, TEMPLATES.groups);
      else if (advTab === "chains") inner = listEditor("chains", "chainsHint", (items) => ({ id: nextId("chain", items), exit_when: {}, entry: {} }), chainBody, TEMPLATES.chains);
      else if (advTab === "patches") inner = listEditor("patches", "patchesHint", (items) => ({ id: nextId("patch", items), merge: {} }), patchBody);
      else if (advTab === "raw") inner = rawEditor();
      else if (advTab === "profile") inner = profileManage();
      else inner = h("div", {},
        sect("sectFilter", listEditor("rules", "rulesHint", (items) => ({ id: nextId("rule", items), when: {}, do: "drop" }), ruleBody, TEMPLATES.rules)),
        sect("sectSort", listEditor("order", "orderHint", (items) => ({ id: nextId("order", items), rank: 30 }), orderBody, TEMPLATES.order)));
      body = h("div", {}, h("div", { class: "tabs sub" }, subs.map(([k, label]) => h("button", { type: "button", class: advTab === k ? "on" : "", onclick: () => { advTab = k; drawEditor(); } }, label))), inner);
    }
    const banner = (cfg.panel || {}).mode === "proxy" && tab !== "start" && tab !== "settings" ? h("div", { class: "msg warn" }, t("proxyOnBanner")) : null;
    editorEl.replaceChildren(
      h("div", { class: "tabs" }, tabs.map(([k, label]) => h("button", { type: "button", class: tab === k ? "on" : "", onclick: () => { tab = k; drawEditor(); } }, label))),
      ...(banner ? [banner] : []), body);
  }

  // ---------- preview ----------
  function schedulePreview() {
    clearTimeout(previewTimer);
    previewTimer = setTimeout(runPreview, 450);
  }
  async function runPreview() {
    const r = await api("preview", { config: cfg, configs: sample || [], subid: lastSubid });
    if (!r.ok) return;
    lastPreview = r.data;
    drawPreviewResult();
    const ae = document.activeElement;
    if (tab === "blocks" && !(ae && editorEl.contains(ae) && /^(INPUT|TEXTAREA)$/.test(ae.tagName))) drawEditor();
  }
  const resultEl = h("div");
  const sampleInfo = h("p", { class: "hint" });
  function drawSampleInfo() { sampleInfo.textContent = sample ? t("sampleN", { n: sample.length }) : t("noSample"); }

  function blockName(id) {                 // "blk-fast--noflag" -> the block's own name
    if (!id || !id.startsWith("blk-")) return null;
    const v = isObj(cfg.blocks) && Array.isArray(cfg.blocks.list) ? cfg.blocks.list : [];
    const base = id.slice(4).replace(/--noflag$/, "");
    const b = v.find((x) => x.id === base);
    if (b) return b.type === "drop" ? t("bRemoved") : (b.name || prettyId(b.id));
    return base === "rest" ? t("bRest") : null;
  }
  const idName = (id) => blockName(id) || prettyId(id || "");
  function explain(c) {
    const bits = [];
    const rule = idName(c.rule || "");
    if (c.action === "drop") bits.push(rule ? t("exp_drop_rule", { rule }) : t("exp_drop"));
    else if (c.action === "pin_top") bits.push(t("exp_top", { rule }));
    else if (c.action === "pin_bottom") bits.push(t("exp_bottom", { rule }));
    else if (c.action === "keep" && rule) bits.push(t("exp_keep_rule", { rule }));
    (c.groups || []).forEach((g) => bits.push(t("exp_group", { g: idName(g) })));
    (c.chains || []).forEach((x) => bits.push(t("exp_chain", { c: prettyId(x) })));
    return bits.length ? bits.join(" · ") : t("exp_kept");
  }

  function drawPreviewResult() {
    const d = lastPreview;
    resultEl.replaceChildren();
    if (!d) return;
    (d.errors || []).forEach((m) => resultEl.append(h("div", { class: "msg err" }, m)));
    (d.warnings || []).forEach((m) => resultEl.append(h("div", { class: "msg warn" }, m)));
    if (!sample) return;
    (d.report.errors || []).forEach((m) => {
      const mm = /^chain ([^ ]+) failed: .*no value for \{account\./.exec(m);
      const auto = cfg.accounts && cfg.accounts.register && cfg.accounts.register.enabled;
      resultEl.append(mm && auto ? h("div", { class: "msg warn" }, t("noAccountYet", { id: mm[1] })) : h("div", { class: "msg err" }, m));
    });
    resultEl.append(h("p", { class: "big-note" }, t("beforeAfter", { a: sample.length, b: d.output.length })));
    resultEl.append(h("h3", {}, t("cfgTable")), h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "#"), h("th", {}, "remark"), h("th", {}, "network"), h("th", {}, t("colWhat")))),
      h("tbody", {}, d.report.configs.map((c) => h("tr", { class: c.action === "drop" ? "drop" : "" },
        h("td", {}, c.index), h("td", {}, c.remark), h("td", { class: "dim" }, c.fields.network || ""),
        h("td", {}, explain(c)))))));
    const pre = h("pre", { hidden: true });
    resultEl.append(h("h3", {}, t("outputs") + " (" + d.output.length + ")"),
      h("div", {}, d.output.map((o, i) => h("div", { class: "out-item", title: t("showJson"), onclick: () => {
        pre.hidden = false; pre.textContent = JSON.stringify(o, null, 2);
      } }, (i + 1) + ". ", o.remarks ?? "(no remark)"))), pre);
  }

  function drawPreview() {
    let remembered = "";
    try { remembered = localStorage.getItem("xsf_subid") || ""; } catch (e) { /* ignore */ }
    const subid = h("input", { type: "text", placeholder: t("subid"), "aria-label": t("subid"), autocomplete: "off", value: lastSubid || remembered });
    const note = h("span", { class: "hint" });
    const doFetch = async () => {
      note.textContent = t("fetching");
      lastSubid = subid.value.trim();
      try { localStorage.setItem("xsf_subid", lastSubid); } catch (e) { /* ignore */ }
      const r = await api("sample", { subid: lastSubid, config: cfg });
      if (r.ok) { setSample(r.data.configs); note.textContent = ""; drawSampleInfo(); runPreview(); } else note.textContent = r.data.error || "error";
    };
    const paste = h("textarea", { rows: 4, spellcheck: "false", placeholder: t("pasteJson") });
    previewEl.replaceChildren(
      h("h3", {}, t("preview")),
      h("p", { class: "hint" }, t("previewHint")),
      h("div", { class: "row" }, subid, h("button", { type: "button", class: "primary", onclick: doFetch }, t("fetch")), note),
      paste,
      h("div", { class: "row" }, h("button", { type: "button", onclick: () => {
        try { const v = JSON.parse(paste.value); setSample(Array.isArray(v) ? v : [v]); note.textContent = ""; drawSampleInfo(); runPreview(); }
        catch (e) { note.textContent = t("jsonBad"); }
      } }, t("useJson"))),
      sampleInfo, resultEl);
    drawSampleInfo();
    drawPreviewResult();
    if (subid.value.trim() && !sample && !autoFetched) { autoFetched = true; doFetch(); }
  }
  let autoFetched = false;

  function changeSummary() {
    const old = prune(JSON.parse(savedSnapshot)), cur = prune(cfg);
    const lines = [];
    const byId = (a) => Object.fromEntries((Array.isArray(a) ? a : []).map((x) => [x.id, x]));
    const same = (a, b) => canon(a) === canon(b);
    const ob = byId((old.blocks || {}).list), nb = byId((cur.blocks || {}).list);
    const bname = (x) => (x.type === "drop" ? t("bRemoved") : x.name || prettyId(x.id));
    Object.keys(nb).forEach((id) => { if (!ob[id]) lines.push(["add", t("sumBlockAdded", { x: bname(nb[id]) })]); else if (!same(ob[id], nb[id])) lines.push(["chg", t("sumBlockChanged", { x: bname(nb[id]) })]); });
    Object.keys(ob).forEach((id) => { if (!nb[id]) lines.push(["del", t("sumBlockRemoved", { x: bname(ob[id]) })]); });
    if (((old.blocks || {}).rest || "keep") !== ((cur.blocks || {}).rest || "keep")) lines.push(["chg", t("sumRest")]);
    ["rules", "groups", "chains", "patches", "order"].forEach((kind) => {
      const o = byId(old[kind]), n = byId(cur[kind]);
      Object.keys(n).forEach((id) => {
        if (!o[id]) lines.push(["add", t("sumOldAdded", { x: prettyId(id) })]);
        else if (o[id].enabled !== false && n[id].enabled === false) lines.push(["off", t("sumOldOff", { x: prettyId(id) })]);
        else if (!same(o[id], n[id])) lines.push(["chg", t("sumOldChanged", { x: prettyId(id) })]);
      });
      Object.keys(o).forEach((id) => { if (!n[id]) lines.push(["del", t("sumOldRemoved", { x: prettyId(id) })]); });
    });
    const sections = [...new Set([...Object.keys(old), ...Object.keys(cur)])].filter((k) => !["blocks", "rules", "groups", "chains", "patches", "order"].includes(k) && !same(old[k], cur[k]));
    if (sections.length) lines.push(["chg", t("sumSettings", { x: sections.join(", ") })]);
    return lines;
  }
  function save() {
    if (tab === "start" || !isDirty()) return doSave();
    const lines = changeSummary();
    const impact = h("p", { class: "hint" }, sample ? t("sumChecking") : t("sumNoSample"));
    const close = () => overlay.remove();
    const overlay = h("div", { class: "overlay", role: "dialog", "aria-modal": "true", "aria-label": t("sumTitle") },
      h("div", { class: "card sum" },
        h("h2", {}, t("sumTitle")),
        lines.length ? h("ul", { class: "sum-list" }, lines.map(([k, x]) => h("li", { class: "sum-" + k }, x))) : h("p", {}, t("sumNothing")),
        impact,
        h("div", { class: "row" },
          h("button", { type: "button", class: "primary", onclick: () => { close(); doSave(); } }, t("save")),
          h("button", { type: "button", onclick: close }, t("cancel")))));
    overlay.addEventListener("keydown", (e) => { if (e.key === "Escape") close(); });
    document.body.append(overlay);
    overlay.querySelector("button.primary").focus();
    if (sample) {
      Promise.all([api("preview", { config: JSON.parse(savedSnapshot), configs: sample, subid: lastSubid }), api("preview", { config: cfg, configs: sample, subid: lastSubid })])
        .then(([a, b]) => {
          if (!a.ok || !b.ok) { impact.textContent = ""; return; }
          impact.textContent = t("sumImpact", { n: sample.length, a: a.data.output.length, b: b.data.output.length });
          const errs = (b.data.errors || []).length + ((b.data.report || {}).errors || []).length;
          if (errs) impact.append(h("span", { class: "danger-text" }, " " + t("sumErrors", { n: errs })));
        });
    }
  }
  async function doSave() {
    const r = await api("save", { config: cfg });
    if (r.ok) {
      savedSnapshot = JSON.stringify(cfg);
      setStatus(t("saved") + (needsRestart() ? " " + t("restartNeeded") : ""), "ok"); updateRestartBtn();
      lastPreview = Object.assign(lastPreview || {}, { errors: [], warnings: r.data.warnings || [] });
      runPreview();
      if (tab === "start" && (wiz.step === 3 || (cfg.panel || {}).mode === "proxy")) { wiz.done = true; drawEditor(); }
    } else {
      setStatus((r.data.errors || [r.data.error || "error"]).length + " ✗", "err");
      lastPreview = Object.assign(lastPreview || {}, { errors: r.data.errors || [r.data.error || "error"], warnings: r.data.warnings || [] });
      drawPreviewResult();
    }
  }

  function datalists() {
    return [
      h("datalist", { id: "dl-fields" }, FIELDS.map((f) => h("option", { value: f }))),
      h("datalist", { id: "dl-types" }, ["leastLoad", "leastPing", "random", "roundRobin"].map((f) => h("option", { value: f }))),
    ];
  }

  function langToggle() {
    return h("button", { type: "button", onclick: () => {
      lang = lang === "fa" ? "en" : "fa";
      try { localStorage.setItem("xsf_lang", lang); } catch (e) { /* ignore */ }
      applyLang(); drawMain();
    } }, lang === "fa" ? "English" : "فارسی");
  }
  function themeToggle() {
    const next = isDark() ? "light" : "dark";                        // the button names what it switches to
    return h("button", { type: "button", title: t("themeTitle"), onclick: () => {
      theme = next;
      try { localStorage.setItem("xsf_theme", theme); } catch (e) { /* ignore */ }
      applyTheme(); drawMain();
    } }, next === "dark" ? "🌙 " + t("themeDark") : "☀ " + t("themeLight"));
  }
  function applyLang() { document.documentElement.lang = lang; document.documentElement.dir = lang === "fa" ? "rtl" : "ltr"; }

  // the profile switcher: one select, plus "+ New profile" (empty, or a copy of the current one without its accounts)
  function profileBox() {
    const sel = h("select", { "aria-label": t("profile"), onchange: () => {
      if (isDirty() && !confirm(t("revert") + "?")) { sel.value = profile; return; }
      profile = sel.value; start();
    } }, profileNames.map((n) => h("option", { value: n }, n === "default" ? t("profileDefault") : n)));
    sel.value = profile;
    const add = h("button", { type: "button", onclick: async () => {
      const name = (prompt(t("profileName")) || "").trim();
      if (!name) return;
      const r = await api("profile-new", { name, copy: confirm(t("profileCopy")) ? profile : undefined });
      if (!r.ok) { alert(r.data.error || "error"); return; }
      profile = name; await start(); alert(t("profileRestart"));
    } }, t("profileNew"));
    return h("span", { class: "profiles" }, sel, add);
  }

  // Advanced > Profile: rename or delete the current profile (kept away from the header so it is not hit by accident)
  function profileManage() {
    const ren = h("button", { type: "button", onclick: async () => {
      const to = (prompt(t("profileName"), profile) || "").trim();
      if (!to || to === profile) return;
      const r = await api("profile-rename", { name: profile, to });
      if (!r.ok) { alert(r.data.error || "error"); return; }
      profile = to; await start(); alert(t("profileRestart"));
    } }, t("profileRename"));
    const del = h("button", { type: "button", class: "danger", onclick: async () => {
      if (!confirm(t("profileDelete", { n: profile }))) return;
      const r = await api("profile-delete", { name: profile });
      if (!r.ok) { alert(r.data.error || "error"); return; }
      profile = "default"; await start(); alert(t("profileRestart"));
    } }, t("profileRemove"));
    if (profile === "default") return h("div", {}, h("p", { class: "hint" }, t("profileDefaultNote")));
    return h("div", {}, h("p", { class: "hint" }, t("profileManageNote", { n: profile })), h("div", { class: "row" }, ren, del));
  }

  function drawMain() {
    const saveBtn = h("button", { type: "button", class: "primary", onclick: save }, t("save"));
    root.replaceChildren(
      h("header", {}, h("h1", {}, t("title"), appVersion ? h("span", { class: "ver", title: t("versionTitle") }, appVersion) : null), profileBox(), statusEl, themeToggle(), langToggle(),
        h("button", { type: "button", onclick: () => { if (!isDirty() || confirm(t("revert") + "?")) start(); } }, t("revert")), saveBtn,
        canRestart ? restartHeaderBtn : null,
        h("button", { type: "button", onclick: async () => { await api("logout", {}); drawLogin(); } }, t("logout"))),
      h("main", {}, editorEl, previewEl), ...datalists());
    drawEditor();
    drawPreview();
    changed();
  }

  function drawLogin(message) {
    applyLang();
    const pw = h("input", { type: "password", autocomplete: "current-password", "aria-label": t("password"), placeholder: t("password") });
    const msg = h("div", { class: "msg err", hidden: !message }, message || "");
    const go = async () => {
      const r = await api("login", { password: pw.value });
      if (r.ok) { csrf = r.data.csrf; start(); } else { msg.hidden = false; msg.textContent = r.status === 401 ? t("wrongPw") : (r.data.error || "error"); }
    };
    pw.addEventListener("keydown", (e) => { if (e.key === "Enter") go(); });
    root.replaceChildren(h("div", { class: "card login" }, h("h1", {}, t("title")), pw, msg,
      h("div", { class: "row" }, h("button", { type: "button", class: "primary", onclick: go }, t("login")), langToggle())));
    pw.focus();
  }

  async function start() {
    const r = await api("state");
    if (r.status === 401) return drawLogin();
    if (!r.ok) { root.replaceChildren(h("div", { class: "card login" }, h("p", {}, t("disabled")))); return; }
    cfg = r.data.config || {};
    const hasWork = ["rules", "groups", "chains", "patches"].some((k) => (cfg[k] || []).length);
    const hasBlocks = isObj(cfg.blocks) && Array.isArray(cfg.blocks.list) && cfg.blocks.list.length;
    const hasPanel = cfg.panel && (cfg.panel.url || (cfg.panel.source === "raw" && cfg.panel.raw_url));
    tab = (hasPanel && (hasBlocks || hasWork)) ? "blocks" : "start";
    savedSnapshot = JSON.stringify(cfg);
    loadedRoute = r.data.route;
    canRestart = !!r.data.can_restart;
    quicDefaults = Array.isArray(r.data.quic_domains) ? r.data.quic_domains : [];
    directRules = Array.isArray(r.data.direct_rules) ? r.data.direct_rules : [];
    if (isObj(r.data.sniffing)) sniffDefaults = r.data.sniffing;
    profileNames = Array.isArray(r.data.profiles) ? r.data.profiles : ["default"];
    profile = r.data.profile || "default";
    syncUrl();
    appVersion = r.data.version ? "v" + r.data.version + (r.data.commit ? " · " + r.data.commit : "") : "";
    loadedServer = JSON.stringify(cfg.server || {});
    lastPreview = { errors: r.data.errors, warnings: r.data.warnings };
    applyLang();
    drawMain();
  }

  async function boot() {
    applyLang();
    const me = await api("me");
    if (me.status === 404) { root.replaceChildren(h("div", { class: "card login" }, h("p", {}, t("disabled")))); return; }
    if (me.ok) { csrf = me.data.csrf; start(); } else drawLogin();
  }
  boot();
})();
