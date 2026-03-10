# qlerky_tui

[![Join our Telegram RU](https://img.shields.io/badge/Telegram-RU-03A500?style=for-the-badge&logo=telegram&logoColor=white&labelColor=blue&color=red)](https://t.me/hidden_coding)
[![Join our Telegram ENG](https://img.shields.io/badge/Telegram-EN-03A500?style=for-the-badge&logo=telegram&logoColor=white&labelColor=blue&color=red)](https://t.me/hidden_coding_en)
[![GitHub](https://img.shields.io/badge/GitHub-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/aero25x)
[![Twitter](https://img.shields.io/badge/Twitter-1DA1F2?style=for-the-badge&logo=x&logoColor=white)](https://x.com/aero25x)
[![YouTube](https://img.shields.io/badge/YouTube-FF0000?style=for-the-badge&logo=youtube&logoColor=white)](https://www.youtube.com/@flaming_chameleon)
[![Reddit](https://img.shields.io/badge/Reddit-FF3A00?style=for-the-badge&logo=reddit&logoColor=white)](https://www.reddit.com/r/HiddenCode/)

**btop-style terminal mail client + TOTP authenticator**

Single file. Zero required dependencies. Pure Python stdlib.  
Manage multiple email inboxes and 2FA codes from your terminal.
<img width="1436" height="1275" alt="image (1)" src="https://github.com/user-attachments/assets/bf4f3f20-b16d-4ad8-9a32-a391178ccfa9" />


---

## Features

- **Multi-account IMAP** — Gmail, Yahoo, Outlook, iCloud, Proton, Yandex, Mail.ru, Fastmail and any IMAP provider. Host and port auto-detected from email domain
- **TOTP authenticator** — live 2FA codes with countdown timer, color changes green → yellow → red as time runs out
- **6-digit code extraction** — scans email subjects and bodies for verification codes, highlights them instantly in the sidebar
- **Universal account import** — type one account, paste a dozen, or enter a file path — all in the same dialog. Separator auto-detected
- **Clipboard copy** — `y` copies current TOTP code, `Y` copies the next one
- **Search / filter** — press `/` to filter accounts or TOTP entries live
- **Auto-refresh** — inbox updates every 15 seconds in background; loaded email bodies are preserved across refreshes
- **Cyrillic keyboard** — all hotkeys work transparently with Russian layout (ЙЦУКЕН)
- **Pure stdlib** — no `pip install` needed to run; `qrcode` or `segno` optional for QR display

<img width="1437" height="1276" alt="image" src="https://github.com/user-attachments/assets/e08c7382-e60b-493e-b0de-c1629d570725" />

---

## Requirements

Python 3.7+ only. No required packages.

Optional — for QR codes in the app/market dialogs:

```bash
pip install qrcode
# or
pip install segno
```

---

## Installation

```bash
curl -O https://raw.githubusercontent.com/Aero25x/qlerky-tui/main/qlerky_tui.py
chmod +x qlerky_tui.py
python3 qlerky_tui.py
```

Config is stored in `~/.config/qlerky_tui/`:
- `accounts.json` — accounts (email + password + IMAP settings)
- `totp.json` — TOTP secrets

---

## Hotkeys

| Key | Action |
|-----|--------|
| `h` / `l` or `1` / `2` / `3` | Switch panel focus |
| `j` / `k` or `↑` / `↓` | Navigate list |
| `Tab` | Cycle focus |
| `Enter` | Connect selected account |
| `a` or `i` | Add / import accounts |
| `d` | Delete selected account |
| `t` | Import TOTP secret |
| `y` | Copy current TOTP code to clipboard |
| `Y` | Copy next TOTP code to clipboard |
| `r` / `F5` | Manual inbox refresh |
| `/` | Search / filter |
| `ESC` | Clear search |
| `p` | Qlerky app info + QR |
| `m` | HC Market |
| `?` | Toggle help overlay |
| `q` / `Ctrl+C` | Quit |

---

## Adding Accounts

Press `a` or `i` to open the universal import dialog.  
Type or paste one line at a time — empty line finishes:

```
you@gmail.com:yourapppassword
you@outlook.com:yourpassword
/home/user/accounts.txt
```

**Supported formats:**

Line format (separator auto-detected: `:` `;` `|` TAB space):
```
email@example.com:password
email@example.com:password:imap.custom.host:993
```

JSON file or direct paste:
```json
[
  {"email": "you@gmail.com", "password": "app-password"},
  {"email": "you@proton.me", "password": "pass", "imap_host": "127.0.0.1", "imap_port": 1143}
]
```

---

## Provider Notes

| Provider | Note |
|----------|------|
| **Gmail** | Requires [App Password](https://myaccount.google.com/apppasswords) — not your main password |
| **Outlook / Hotmail** | Requires App Password if 2FA is enabled |
| **iCloud** | Requires App Password from appleid.apple.com |
| **Proton Mail** | Requires [Proton Bridge](https://proton.me/mail/bridge) running locally on `127.0.0.1:1143` |
| **Yandex** | Enable IMAP in settings first |

> Passwords are stored in plain text in `~/.config/qlerky_tui/accounts.json`. Secure your home directory accordingly.

---

## Built by

[HiddenCode](https://t.me/hidden_coding) — privacy-first tools for people who value their data.

---
---

# qlerky_tui

**Терминальный почтовый клиент + TOTP аутентификатор в стиле btop**

Один файл. Никаких обязательных зависимостей. Чистый Python stdlib.  
Управляй несколькими почтовыми ящиками и 2FA-кодами прямо из терминала.

---

## Возможности

- **Мульти-аккаунт IMAP** — Gmail, Yahoo, Outlook, iCloud, Proton, Яндекс, Mail.ru, Fastmail и любой IMAP-провайдер. Хост и порт определяются автоматически по домену
- **TOTP аутентификатор** — живые 2FA-коды с таймером обратного отсчёта, цвет меняется зелёный → жёлтый → красный по мере истечения времени
- **Извлечение 6-значных кодов** — сканирует темы и тела писем на коды верификации, подсвечивает их мгновенно в боковой панели
- **Универсальный импорт аккаунтов** — введи один, вставь десяток, или укажи путь к файлу — всё в одном диалоге. Разделитель определяется автоматически
- **Копирование в буфер** — `y` копирует текущий TOTP-код, `Y` — следующий
- **Поиск и фильтрация** — нажми `/` для фильтрации аккаунтов или TOTP-записей в реальном времени
- **Авто-обновление** — инбокс обновляется каждые 15 секунд в фоне, загруженные тела писем сохраняются между обновлениями
- **Кириллица** — все горячие клавиши работают с русской раскладкой (ЙЦУКЕН) прозрачно
- **Чистый stdlib** — не требует `pip install` для запуска; `qrcode` или `segno` опционально для QR

---

## Требования

Только Python 3.7+. Никаких обязательных пакетов.

Опционально — для QR-кодов в диалогах приложений:

```bash
pip install qrcode
# или
pip install segno
```

---

## Установка

```bash
curl -O https://raw.githubusercontent.com/Aero25x/qlerky-tui/main/qlerky_tui.py
chmod +x qlerky_tui.py
python3 qlerky_tui.py
```

Конфиг хранится в `~/.config/qlerky_tui/`:
- `accounts.json` — аккаунты (email + пароль + настройки IMAP)
- `totp.json` — TOTP-секреты

---

## Горячие клавиши

| Клавиша | Действие |
|---------|----------|
| `h` / `l` или `1` / `2` / `3` | Переключить фокус панели |
| `j` / `k` или `↑` / `↓` | Навигация по списку |
| `Tab` | Цикл фокуса |
| `Enter` | Подключиться к выбранному аккаунту |
| `a` или `i` | Добавить / импортировать аккаунты |
| `d` | Удалить выбранный аккаунт |
| `t` | Импорт TOTP-секрета |
| `y` | Скопировать текущий TOTP-код в буфер обмена |
| `Y` | Скопировать следующий TOTP-код в буфер обмена |
| `r` / `F5` | Ручное обновление инбокса |
| `/` | Поиск / фильтр |
| `ESC` | Сбросить поиск |
| `p` | Информация о приложении Qlerky + QR |
| `m` | HC Market |
| `?` | Показать / скрыть справку |
| `q` / `Ctrl+C` | Выйти |

---

## Добавление аккаунтов

Нажми `a` или `i` для открытия универсального диалога импорта.  
Вводи строки по одной — пустая строка завершает ввод:

```
you@gmail.com:парольприложения
you@outlook.com:пароль
/home/user/accounts.txt
```

**Поддерживаемые форматы:**

Построчный формат (разделитель определяется автоматически: `:` `;` `|` TAB пробел):
```
email@example.com:пароль
email@example.com:пароль:imap.custom.host:993
```

JSON-файл или прямая вставка:
```json
[
  {"email": "you@gmail.com", "password": "пароль-приложения"},
  {"email": "you@proton.me", "password": "пароль", "imap_host": "127.0.0.1", "imap_port": 1143}
]
```

---

## Заметки по провайдерам

| Провайдер | Заметка |
|-----------|---------|
| **Gmail** | Требует [Пароль приложения](https://myaccount.google.com/apppasswords) — не основной пароль |
| **Outlook / Hotmail** | Требует Пароль приложения если включена 2FA |
| **iCloud** | Требует Пароль приложения с appleid.apple.com |
| **Proton Mail** | Требует запущенный [Proton Bridge](https://proton.me/mail/bridge) на `127.0.0.1:1143` |
| **Яндекс** | Сначала включи IMAP в настройках почты |

> Пароли хранятся в открытом виде в `~/.config/qlerky_tui/accounts.json`. Защити свою домашнюю директорию соответствующим образом.

---

## Создано

[HiddenCode](https://t.me/hidden_coding) — инструменты с приоритетом приватности для людей, которые ценят свои данные.


[![Join our Telegram RU](https://img.shields.io/badge/Telegram-RU-03A500?style=for-the-badge&logo=telegram&logoColor=white&labelColor=blue&color=red)](https://t.me/hidden_coding)
[![Join our Telegram ENG](https://img.shields.io/badge/Telegram-EN-03A500?style=for-the-badge&logo=telegram&logoColor=white&labelColor=blue&color=red)](https://t.me/hidden_coding_en)
[![GitHub](https://img.shields.io/badge/GitHub-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/aero25x)
[![Twitter](https://img.shields.io/badge/Twitter-1DA1F2?style=for-the-badge&logo=x&logoColor=white)](https://x.com/aero25x)
[![YouTube](https://img.shields.io/badge/YouTube-FF0000?style=for-the-badge&logo=youtube&logoColor=white)](https://www.youtube.com/@flaming_chameleon)
[![Reddit](https://img.shields.io/badge/Reddit-FF3A00?style=for-the-badge&logo=reddit&logoColor=white)](https://www.reddit.com/r/HiddenCode/)

