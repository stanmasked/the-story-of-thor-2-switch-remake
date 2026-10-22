# The Story of Thor 2 — Stage 52: единая приватная проверка захватов Saturn

Дата: 22 октября 2026 года.

## Статус

Проверка Stage 51 завершена: 1060/1060 синтетических тестов. Исходный ISO Sega Saturn MK-81302 существует только в приватном рабочем окружении. Его SHA-256 совпал с зафиксированным значением `25b0b2774d4621bd9f95a01fc5420ded37b481b61b3cdf515360d82b2cb7bb0d`. В заголовке диска указано первое чтение в `0x06004000`, а первым обычным файлом корневого каталога является `0TH2.BIN`.

Запускаемого эмулятора Saturn в текущем окружении нет; реальных RAM-снимков, VRAM-снимков и журнала инструкций пока **не получено**. Stage 52 — инструмент независимой проверки **будущего приватного набора файлов**. Не следует выдавать результаты синтетического CI за настоящий захват.

## Реализованный валидатор

Новый `tools/stage52_private_saturn_capture_bundle_audit.py` объединяет четыре проверки:

1. **Stage 51:** проверка закреплённой контрольной суммы ISO и статической карты первой загрузки Saturn.
2. **Stage 50:** совпадение 12 контрольных образцов инструкций Stage45/46 с 1-МиБ снимком SH-2 High Work RAM.
3. **Stage 48:** реконструкция VDP1 VRAM до/после по 8-байтным дескрипторам и приватному исходному потоку 32-байтных команд. Внешний R5 равен числу дескрипторов; внутренний R2 определяет количество команд.
4. **Stage 49:** проверка последовательности SH-2-PC, восьми 32-битных записей на команду, регистров и значений команд в журнале JSONL.

Помимо этого проверяются SHA-256 всех предоставленных файлов, совместимость датчиков последовательности событий, номера кадров и циклов, декларация имени/версии/хеша сборки эмулятора, а также выбор HLE или внешнего BIOS. Отчёт не содержит исполняемых байтов, точных адресов, дампов, исходных значений команд или путей к приватным файлам.

Важная разница: **контрольная сумма защищает от неслучайной подмены конкретного файла, но не доказывает, что его записал эмулятор**. Все метаданные о происхождении представлены пользователем/инструментом захвата и остаются непроверенными. Даже при `all_operator_supplied_offline_checks_consistent=true` поля `authenticated_emulator_trace_observed`, `sh2_gameplay_execution_proven` и `boot_file_transfer_dynamically_verified` остаются `false`.

## Формат приватного session.json

Содержимое следующего примера **искусственное**. Настоящие хеши надо вычислить локально из каждого отдельного файла после окончательного захвата:

```json
{
  "schema_version": 1,
  "emulator": {
    "name": "SyntheticSaturnTest",
    "version": "0.1-test",
    "build_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "bios_mode": "hle",
    "bios_sha256": null
  },
  "capture": {
    "frame_before": 100,
    "frame_after": 101,
    "cycle_ram": 990,
    "cycle_vram_before": 1000,
    "cycle_trace_start": 1001,
    "cycle_trace_end": 1500,
    "cycle_vram_after": 1501
  },
  "artifacts": {
    "high_ram": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "vram_before": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "vram_after": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "trace_jsonl": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "descriptor_manifest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "source_commands": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  }
}
```

Для внешнего BIOS необходимо `bios_mode=external` и его SHA-256; для HLE — `bios_sha256=null`. Значения кадра и цикла должны быть истинными показаниями одной и той же системы отсчёта эмулятора. Журнал должен находиться во временном интервале между VRAM before и VRAM after, а снимок RAM должен быть снят не позже VRAM before. Это **заявленное временное упорядочение**, не криптографическая аттестация.

## Приватный запуск

```sh
python tools/stage52_private_saturn_capture_bundle_audit.py \
  --iso-private "/private/The Story of Thor 2.iso" \
  --session-private /private/stage52/session.json \
  --high-ram-private /private/stage52/highram.private-snapshot \
  --before-vram-private /private/stage52/before.vram \
  --after-vram-private /private/stage52/after.vram \
  --manifest-private /private/stage52/descriptors.json \
  --trace-jsonl-private /private/stage52/sh2-events.private-trace.jsonl \
  --source-commands-private /private/stage52/source-commands.bin \
  --output-private /private/stage52/stage52.private-capture-audit.json
```

Все пути указывают на **локальные файлы вне репозитория**. Требуются полные дампы SH-2 High Work RAM (1048576 байт) и два полных дампа VDP1 VRAM (по 524288 байт). Входной манифест дескрипторов соответствует Stage48; JSONL-формат событий соответствует Stage49. Исходные команды необязательны только для частичной диагностики; без них полный вывод `all_operator_supplied_offline_checks_consistent` не может быть true.

Выходной файл создаётся только новым, с правами 0600 без перезаписи. Оригинальный ISO, BIOS, текстуры, RAM, VRAM и подлинные события SH-2 не должны передаваться в публичные Pull Request, CI-артефакты или логи.

## Тесты и ограничение задачи

Добавлены 29 синтетических тестов: полное согласование искусственного набора, изменения RAM/VRAM и адресов PC, исправленный R2/R5, отсутствие исходных слов, контроль файловых SHA-256, обнаружение изменений после вычисления хеша, неупорядоченные кадры/циклы, некорректный BIOS, дубли ключей JSON и отсутствие приватных байтов в агрегированном отчёте.

Вслед за Stage52 нужен **настоящий загрузившийся Sega Saturn-эмулятор**, поддерживающий отладчик или извлечение RAM/VDP1 и журналирование SH-2. Среди доступных исследовательских путей: Mednafen с Saturn debugger или Yabause (включая HLE BIOS при отсутствии приватного BIOS). Настоящие снимки, сведения о сборке и результат выполнения должны быть получены отдельно; это не имитируется тестами.
