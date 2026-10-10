# B2Bee

**Флаг:** `avito{juSt_34Sy_biG_DISCoUNt}`

B2Bee принимает Java-плагины и проверяет их байткод через ASM. Проверка разрешает весь
префикс `java/lang`, включая reflection, и пропускает строковые константы с именами
запрещённых классов. Этого достаточно, чтобы прочитать `/flag.txt`.

## Обход проверки

`POST /api/plugins/run` принимает JAR (`plugin`), имя класса (`entryClass`) и корзину
(`cart`). Класс должен реализовывать `DiscountPlugin`.

Сканер проверяет владельцев инструкций байткода. Вызов `Files.readAllBytes` напрямую
он блокирует, но ту же операцию можно вызвать через `Class.forName` и `Method.invoke`:
для сканера это обращения к разрешённым `java/lang/Class` и `java/lang/reflect/Method`.
Имена `java.nio.file.Files` и `java.lang.Runtime` остаются обычными строками.

Плагин пробует чтение через `Files`, `FileInputStream` и `Runtime.exec`, возвращая
результат в `PluginResult.message`. Отдельный канал передачи данных не нужен.

Сканер также запрещает `invokedynamic`. Поэтому в плагине нет лямбд и ссылок на
методы, строки собираются через `StringBuilder`, а сборка использует
`-XDstringConcat=inline`.

## Запуск

Нужны JDK 21 и `curl`. Скрипт сборки скачивает ASM 9.7 и сверяет SHA-256:

```bash
bash b2bee/exploit/build.sh
```

Проверка должна принять плагин и отклонить контрольный класс с прямым вызовом
`java.nio.file`:

```text
RESULT: SCAN PASSED
SCAN BLOCKED [blocked-direct-call]
```

Полная сборка, проверка и отправка на работающий экземпляр:

```bash
uv run python b2bee/solve_b2bee.py --help
uv run python b2bee/solve_b2bee.py
```

В `cart` должен быть хотя бы один товар: с пустой корзиной сервис не запускает плагин.
Флаг находится в `result.message`.

## Файлы

- [solve_b2bee.py](solve_b2bee.py) — сборка и отправка плагина.
- [SeasonalDiscountPlugin.java](exploit/src/example/SeasonalDiscountPlugin.java) — плагин.
- [build.sh](exploit/build.sh) и [harness](exploit/harness/) — локальная проверка.
- [PluginScanner.java](marketplugins/PluginScanner.java) и
  [SandboxPolicy.java](marketplugins/SandboxPolicy.java) — исходная проверка сервиса.

Запрет отдельных инструкций не изолирует загруженный код. Здесь нужна отдельная JVM
с ограниченными правами на файловую систему; сужение списка разрешённых классов само
по себе такую изоляцию не заменяет.
