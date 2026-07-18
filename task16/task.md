# Task16 — SmartHive / умный леток

**Avito CTF 2026 · web (Spring Boot, broken access control)**

## Легенда
На северной пасеке пчёлы завели умные устройства: камеры вокруг улья, датчики в сотах и **умные летковые ворота** (камера распознаёт своих → ворота открываются). Друг подслушал учётку одной пчелы, нашли сайт системы, но для **управления летком не хватает прав**.

## Доступ
- creds: `bee4 : MusicIsLife123` (низкая роль)
- сайт: `https://smarthive-vzzgazuy.avitoctf.ru/`
- исходники: `task16/smarthive/` (Spring Boot, `ru.avito.iot.hivehub`)

## Цель
Обойти контроль доступа / повысить роль, получить управление летковыми воротами → флаг `avito{...}` (см. `FlagResolver`).

## Гипотезы (по структуре исходников)
- broken access control в `DeviceController`/`OperationsController` (нет проверки роли на управлении устройством);
- манипуляция сессией/ролью (`SessionService`, `Role`, mass-assignment в `AccountService`);
- IDOR по device id; debug-эндпоинты (`DebugAuditLog`, `LogController`, `MaintenanceBot`);
- сид-данные/флаг в `DatabaseSeeder`/`FlagResolver`/`application.properties`.
