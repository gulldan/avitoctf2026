# Ghost Font — технический разбор

**Флаг:** `avito{SM4RT3R_TH4N_AI}`
**Класс:** steganography / image forensics / signal processing

## Краткое техническое резюме

Входной артефакт — статический PNG-кадр монохромной анимации Ghost Font. Сообщение кодируется не
цветовыми каналами или метаданными, а двумя пространственными признаками: фазой регулярной решётки с
периодом 6 пикселей и корреляцией со смещённой копией исходного точечного поля.

Для восстановления текста применяются matched filtering по несущей `exp(-2πi·y/6)` и
FFT-автокорреляция. Перемножение двух независимо полученных score map подавляет фон и восстанавливает
строки `SM4RT3R / TH4N AI`.

---

## 1. Контекст и цель

Дан файл `ghost_screenshot.png` размером около 988 КБ — один браузерный кадр Ghost Font. Требуется
восстановить сообщение из псевдослучайного поля чёрно-белых точек.

Статический кадр визуально близок к noise pattern, поэтому стандартный OCR не выделяет текст. Анализ
должен определить физический канал кодирования и построить воспроизводимый decoder.

## 2. Reconnaissance и attack surface

`decode_ghost.py` сначала валидирует контейнер PNG:

```text
Parsed end: 988089; file size: 988089; trailing bytes: 0
```

CRC всех PNG chunks корректны, trailing data после `IEND` отсутствует. `strings`, `exiftool` и
`binwalk` также не обнаруживают embedded payload или значимые metadata. Это исключает наиболее
очевидные container-level каналы.

Изображение монохромное; анализ RGB channels и bit planes не обнаруживает LSB payload. При этом
downsampling и density map слабо проявляют контуры текста. Следовательно, полезный сигнал находится
в геометрии регулярного point pattern, а не в интенсивности отдельных pixels.

## 3. Анализ и проверка гипотез

### 3.1. Нормализация изображения

Браузерная рамка удаляется, после чего canvas проходит resampling в исходное разрешение `1280×720`.
Привязка к `CELL_SIZE = 6` обязательна: произвольный resize разрушает фазовый признак решётки.

### 3.2. Phase-based matched filtering

Точки расположены на решётке с периодом 6 пикселей. Область сообщения отличается вертикальным
phase offset относительно background cells. Функция `carrier_score`:

1. бинаризует point field;
2. умножает его на комплексную несущую `exp(-2πi·y/6)`;
3. оценивает и вычитает background phase по рамке canvas;
4. применяет box smoothing с радиусами 24 и 9.

Полученная карта `ghost_coarse.png` уже содержит читаемый текст, но имеет низкую spatial resolution.

### 3.3. Поиск смещённой копии

Второй признак — overlay той же реализации random field со сдвигом. Горизонтальный offset
`SIGNAL_X_OFFSET = 294` определяется структурой atlas; вертикальный offset вычисляется функцией
`find_vertical_shift` через circular FFT correlation. Максимум корреляции соответствует
`Δy = 706` для периода 720.

Локальное сравнение исходного поля и копии со смещением `(Δx=294, Δy=706)` даёт резкую, но шумную
mask сообщения.

### 3.4. Fusion независимых признаков

Phase score устойчив к noise, но размывает границы. Correlation score сохраняет границы, но содержит
false positives. Финальный decoder перемножает обе карты:

```python
rendered *= coarse_mask
```

Сигнал сохраняется только в областях, подтверждённых обоими detectors. После thresholding и crop
восстанавливаются строки:

```text
SM4RT3R
TH4N AI
```

## 4. Корневая причина

Ghost Font использует два независимых spatial channels:

1. **Grid phase modulation.** Cells внутри glyph mask имеют вертикальный phase offset на решётке с
   периодом 6 пикселей. Признак выделяется с помощью matched filter на соответствующей carrier frequency.
2. **Shifted-pattern correlation.** Glyph mask содержит смещённую копию того же random field.
   Autocorrelation выявляет offset и локализует совпадающие regions.

Оба признака присутствуют в одном кадре, поэтому temporal sequence анимации для восстановления не
требуется.

## 5. Эксплуатация

Из корня репозитория:

```bash
uv run python task2/decode_ghost.py \
  task2/ghost_screenshot.png \
  -o task2/ghost_decoded.png
```

Pipeline скрипта:

1. `inspect_png` — parse chunks, CRC validation, trailing-data check;
2. `normalize_canvas` — crop browser chrome и grid-aligned resampling;
3. `carrier_score` — phase score для периода 6;
4. `find_vertical_shift` — FFT correlation и поиск `Δy`;
5. `recover_visual` — correlation map и score fusion;
6. `save_cropped_visual` — threshold, crop и сохранение результата.

Leetspeak-нормализация `SM4RT3R_TH4N_AI` даёт итоговое содержимое флага.

## 6. Флаг

```text
avito{SM4RT3R_TH4N_AI}
```

## 7. Выводы и рекомендации

- При image forensics следует отдельно проверять container-level, pixel-level и spatial-frequency
  channels. Отсутствие metadata или LSB payload не исключает structural steganography.
- Регулярный lattice pattern необходимо анализировать в frequency domain: phase response и
  autocorrelation информативнее прямого averaging.
- Fusion независимых detectors повышает signal-to-noise ratio: устойчивый phase score подавляет
  correlation noise, а correlation map восстанавливает резкие границы.
- Для воспроизводимости preprocessing должен сохранять исходную grid phase; произвольный resampling
  способен полностью уничтожить полезный сигнал.

## 8. Файлы для воспроизведения

Version-controlled artifacts:

- `task2/decode_ghost.py` — полный recovery pipeline; зависимости `numpy` и `Pillow` определены в
  корневом `pyproject.toml`.

Исходный challenge image `task2/ghost_screenshot.png` не входит в version-controlled
набор. `ghost_decoded.png` и `ghost_coarse.png` генерируются при запуске solver.
