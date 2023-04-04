## Описание

#### **caged** – это программа для безопасной установки пакетов из публичных репозиториев (PyPI, npm, crates.io, etc.)

## Установка

```shell
pip install caged
```

## Использование

```shell
caged pip install <имя_пакета> <аргументы_pip>
```

```shell
caged npm install <имя_пакета> <аргументы_npm>
```

## Принцип работы

- **Статический анализ.** caged проверяет метаданные и исходный код пакета на совпадение с заранее заданными правилами. Метаданные пакета проверяются с помощью программ на языке Python. Исходный код пакета проверяется с помощью Open Source программы semgrep с заранее заданными правилами.
- **Динамический анализ.** Динамический анализ кода осуществляется с помощью контейнеризации. Программа caged запускает Docker-контейнер (для изоляции от основной системы), в котором устанавливается и запускается исследуемый пакет, после чего собирается информация о том, какие ресурсы системы (файлы, команды) или внешние ресурсы он использует. Для этого используется открытая технология gVisor, позволяющая выполнять контейнеры более легковесным способом, чем при обычной виртуализации. Так достигается максимальная безопасность и сокращение времени проверки.
- **Обработка данных.** Данные, полученные с помощью динамического анализа, сохраняются в формате JSON. После этого, полученные данные векторизуются (превращаются в список вида {"DNS Records": 123}, хранящий в себе числовые метрики пакета). Далее метрики обрабатываются с помощью заранее обученной модели машинного обучения, которая выдает результат логического типа (является ли пакет вредоносным или нет).
- Ели все статические и динамические проверки пакетом пройдены успешно, то запускается официальный установщик пакетов для данной экосистемы.]