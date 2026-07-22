# Майя / Майес — технический разбор

**Флаг:** `avito{M4Y35_is_GO0d_BuT_a3S_IS_Bet73r}`
**Класс:** cryptography / chosen-plaintext oracle / custom block cipher cryptanalysis

## Краткое техническое резюме

Mayes обрабатывает 128-bit block как четыре независимых 32-bit words. Для каждого word применяется
один byte-substitution layer с key whitening через XOR, затем affine transformation над
`Z/256Z`. Между words отсутствует diffusion.

Cipher parameters постоянны между sessions, а session key восстанавливается из одного chosen
plaintext `E_K(0)`. Login endpoint возвращает encryption неверного guess, поэтому один failed attempt
даёт необходимый known pair. Текущий challenge после этого расшифровывается алгебраически и
отправляется второй попыткой.

---

## 1. Контекст и цель

Service:

```bash
nc maya-iiklm8rm.avitoctf.ru 30013
```

Initial access secret:

```text
v3FpEne80zLFyP1rOfj5rQ
```

После initial authentication доступны modes `login`, `debug`, `exit`:

- `login` выдаёт encrypted random challenge и допускает пять guesses;
- при неверном guess сервер возвращает его encryption под текущим session key и генерирует новый
  challenge;
- `debug` предоставляет unlimited encryption oracle с key предыдущей session.

`debug` используется для восстановления постоянной cipher specification. `login` предоставляет
chosen-plaintext oracle с target session key.

## 2. Reconnaissance и attack surface

Измерения через debug oracle дают следующие invariants.

### 2.1. Независимые 32-bit words

Изменение input byte `i` влияет только на output word `i // 4`. Следовательно, 16-byte block
разделён на четыре независимых permutations без inter-word diffusion.

### 2.2. Cardinality fingerprint

При переборе одного input byte и фиксации остальных нулями число distinct values каждого output byte
даёт matrix `log2(cardinality)`:

```text
[[8,5,8,7],
 [7,8,8,6],
 [7,8,4,7],
 [7,7,8,8]]
```

Cardinalities являются степенями двойки. Преобразование не XOR-affine, хотя каждый word остаётся
bijective и демонстрирует strong avalanche в bit representation.

### 2.3. Опровержение GF(2)-модели

Hypothesis о two-round SPN над GF(2) проверяется на двумерной сетке `256×256`. Для ожидаемого XOR
decomposition inverse transform должен иметь kernel dimension 8; фактическая dimension равна 1.
Следовательно, mixing layer не является linear over GF(2) или GF(2⁸).

Permutation, соответствующая increment одного input byte, имеет order 128; для другого output byte
order равен 16. XOR translation всегда имеет order 2, тогда как 128 и 16 являются divisors 256. Это
указывает на addition modulo 256.

## 3. Анализ и проверка гипотез

Для каждого 4-byte word encryption описывается:

```text
s_i = S(p_i XOR k_i)
c_j = (sum_i M[j][i] * s_i + d_j) mod 256
```

где:

- `S` — byte permutation;
- `k_i` — bytes session key;
- `M` — invertible `4×4` matrix над `Z/256Z`;
- `d` — affine constant.

Observed cardinality согласуется с 2-adic valuation coefficients:

```text
rank_effect = 8 - v2(M[j][i])
```

Odd coefficient даёт 256 distinct values, coefficient divisible by 16 — 16 values. Высокая
algebraic degree над GF(2) возникает из carry propagation в modular addition, а не из нескольких
nonlinear rounds.

Восстановленная matrix:

```text
[[  1, 86, 138, 206],
 [184,  1,   1, 142],
 [ 53,135, 112,   1],
 [ 98,132,  34,  41]]
```

`recover_full.py` варьирует каждый input byte, выбирает full-rank reference channel и восстанавливает
columns `M`, byte lookup tables и `d`. Проверка на 300 random plaintexts даёт 300/300 совпадений.

Сравнение трёх sessions показывает:

- matrix `M` постоянна;
- normalized affine constants постоянны;
- lookup tables разных sessions отличаются input XOR shift;
- shift совпадает с XOR corresponding key bytes.

Следовательно, единственный session-specific secret — четыре 32-bit word keys.

## 4. Корневая причина

Cipher допускает direct key recovery по нескольким причинам:

1. block partitioning исключает diffusion между четырьмя words;
2. каждый word содержит только один nonlinear substitution layer;
3. последующий mixing layer affine и invertible over `Z/256Z`;
4. все structural parameters постоянны между sessions;
5. login error path предоставляет chosen-plaintext encryption под target key.

Для zero plaintext:

```text
E_K(0) = M * S(K) + d mod 256
```

Поэтому:

```text
S(K) = M^-1 * (E_K(0) - d) mod 256
K    = S^-1(S(K))
```

После recovery `K` любой challenge расшифровывается напрямую:

```text
S(P XOR K) = M^-1 * (C - d) mod 256
P          = K XOR S^-1(M^-1 * (C - d))
```

Exhaustive key search не требуется.

## 5. Эксплуатация

Постоянная specification сохранена в `task10/mayes_spec.json`. End-to-end solver:

```bash
uv run python task10/solve.py
```

Attack flow:

1. пройти initial authentication значением `v3FpEne80zLFyP1rOfj5rQ`;
2. выбрать `login` и прочитать first challenge;
3. отправить неверный all-zero guess;
4. получить `E_K(0)` и новый challenge;
5. для каждого word вычислить session key через `M^-1` и inverse lookup tables;
6. локально проверить `encrypt(K, 0) == E_K(0)`;
7. расшифровать актуальный challenge;
8. проверить `encrypt(K, plaintext) == challenge`;
9. отправить plaintext второй попыткой.

Specification recovery выполняется отдельно через debug oracle и сохраняет для каждого word:

- `M` и `M^-1`;
- affine vector `d`;
- forward и inverse byte tables.

Локальная model validation включает 200 random encryptions, 200 decryptions и recovery key из
`E(0)`.

## 6. Флаг

```text
avito{M4Y35_is_GO0d_BuT_a3S_IS_Bet73r}
```

## 7. Выводы и рекомендации

- Custom cryptographic designs не должны использоваться вместо стандартизованных constructions с
  публичным cryptanalysis; для 128-bit blocks следует применять AES в authenticated mode.
- Strong bit-level avalanche не доказывает достаточное число rounds или resistance to structural
  attacks. Modular carries могут имитировать высокую algebraic degree.
- Diffusion должна охватывать весь block; независимые words уменьшают analysis complexity и key
  recovery до четырёх изолированных problems.
- Diagnostic/error interfaces не должны предоставлять encryption oracle под production session key.
- Cryptanalysis следует проверять в нескольких algebraic models: failure GF(2) decomposition и orders
  induced permutations позволили идентифицировать arithmetic over `Z/256Z`.

## 8. Файлы для воспроизведения

Version-controlled artifacts:

- `task10/solve.py` — protocol client, session-key recovery и challenge decryption.
- `task10/mayes_spec.json` — восстановленные `M`, `M^-1`, `d`, forward и inverse tables для четырёх
  words.
- `task10/task.md` — исходное условие и network parameters.
