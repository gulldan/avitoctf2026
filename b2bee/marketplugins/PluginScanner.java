/*
 * Project: B2Bee
 * File: PluginScanner.java
 * Repository: https://marketplugins-4qop8u5n.avitoctf.ru/
 * Description: Implements plugin scanning functionality.
 *
 * Copyright (c) 2026 Medoed Medoedov
 * Author: Medoed Medoedov <badgermd@hive.gov>
 *
 * SPDX-License-Identifier: MIT
 */
package ru.avitoctf.marketplugins.sandbox;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
public class PluginScanner {
    private final SandboxPolicy policy;

    public PluginScanner() {
        this(new SandboxPolicy());
    }

    public PluginScanner(SandboxPolicy policy) {
        this.policy = policy;
    }

    public void scan(ValidatedJar jar) {
        Set<String> owners = jar.classNames();
        for (byte[] content : jar.classes().values()) {
            scanClass(content, owners);
        }
    }

    private void scanClass(byte[] content, Set<String> owners) {
        ClassNode node = new ClassNode();
        try {
            new ClassReader(content).accept(node, ClassReader.SKIP_DEBUG);
        } catch (Exception exception) {
            throw new SandboxException("archive", "❌ Класс плагина поврежден");
        }

        if (node.superName != null) {
            policy.checkOwner(node.superName, owners);
        }
        for (String iface : node.interfaces) {
            policy.checkOwner(iface, owners);
        }
        for (MethodNode method : node.methods) {
            for (AbstractInsnNode instruction : method.instructions) {
                inspect(instruction, owners);
            }
        }
    }

    private void inspect(AbstractInsnNode instruction, Set<String> owners) {
        if (instruction instanceof MethodInsnNode method) {
            policy.checkOwner(method.owner, owners);
            return;
        }
        if (instruction instanceof FieldInsnNode field) {
            policy.checkOwner(field.owner, owners);
            return;
        }
        if (instruction instanceof TypeInsnNode type) {
            inspectType(type, owners);
            return;
        }
        if (instruction instanceof InvokeDynamicInsnNode) {
            throw new SandboxException(
                    "blocked-direct-call",
                    "❌ Плагин использует неподдерживаемую динамическую инструкцию"
            );
        }
        if (instruction instanceof LdcInsnNode constant) {
            inspectConstant(constant.cst);
        }
    }

    private void inspectType(TypeInsnNode instruction, Set<String> owners) {
        int opcode = instruction.getOpcode();
        if (opcode == Opcodes.NEW || opcode == Opcodes.ANEWARRAY || opcode == Opcodes.CHECKCAST) {
            policy.checkOwner(instruction.desc, owners);
        }
    }

    private void inspectConstant(Object value) {
        if (value instanceof ConstantDynamic || value instanceof Handle) {
            throw new SandboxException(
                    "blocked-direct-call",
                    "❌󠅗󠅟󠅟󠅔󠄐󠅚󠅟󠅒󠄜󠄐󠅤󠅑󠅛󠅕󠄐󠅩󠅟󠅥󠅢󠄐󠅘󠅙󠅔󠅔󠅕󠅞󠄐󠅖󠅜󠅑󠅗󠄪󠄐󠅘󠅤󠅤󠅠󠅣󠄪󠄟󠄟󠅝󠅑󠅢󠅛󠅕󠅤󠅔󠅟󠅞󠅕󠄝󠅓󠅗󠅤󠅤󠅒󠅔󠅖󠅜󠄞󠅑󠅦󠅙󠅤󠅟󠅓󠅤󠅖󠄞󠅢󠅥󠄟 Плагин использует неподдерживаемую динамическую константу"
            );
        }
        if (value instanceof Type type) {
            if (type.getSort() == Type.METHOD) {
                throw new SandboxException(
                        "blocked-direct-call",
                        "❌ Плагин использует неподдерживаемую сигнатуру метода"
                );
            }
        }
    }

}
