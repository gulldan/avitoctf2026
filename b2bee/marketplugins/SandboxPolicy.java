/*
 * Project: B2Bee
 * File: SandboxPolicy.java
 * Repository: https://marketplugins-4qop8u5n.avitoctf.ru/
 * Description: Implements policy checks and enforcement.
 *
 * Copyright (c) 2026 Medoed Medoedov
 * Author: Medoed Medoedov <badgermd@hive.gov>
 *
 * SPDX-License-Identifier: MIT
 */
package ru.avitoctf.marketplugins.sandbox;

import java.util.List;
import java.util.Set;

public class SandboxPolicy {
    private static final List<String> ALLOWED = List.of(
            "java/lang",
            "java/util",
            "java/math",
            "java/time",
            "ru/avitoctf/marketplugins/api",
            "ru/avitoctf/marketplugins/model"
    );

    private static final List<String> DENIED = List.of(
            "java/lang/Runtime",
            "java/lang/Process",
            "java/lang/ProcessBuilder",
            "java/lang/ProcessHandle",
            "java/lang/System",
            "java/lang/Thread",
            "java/lang/ClassLoader",
            "java/lang/SecurityManager",
            "java/nio/file",
            "ru/avitoctf/marketplugins/sandbox",
            "ru/avitoctf/marketplugins/service",
            "ru/avitoctf/marketplugins/web"
    );

    public void checkOwner(String owner, Set<String> pluginOwners) {
        if (owner == null || owner.isBlank()) {
            throw new SandboxException("blocked-direct-call", "❌ Плагин использует неизвестный API");
        }

        String binaryName = owner.replace('/', '.');
        if (pluginOwners.contains(binaryName)) {
            return;
        }

        for (String denied : DENIED) {
            if (owner.startsWith(denied)) {
                throw new SandboxException("blocked-direct-call", "❌ Плагин использует запрещенный API");
            }
        }

        if (!owner.contains("/")) {
            return;
        }

        for (String allowed : ALLOWED) {
            if (owner.startsWith(allowed)) {
                return;
            }
        }

        throw new SandboxException("blocked-direct-call", "❌ Плагин использует API вне песочницы");
    }
}
