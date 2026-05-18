Co2H — HTML Help (.chm) source
==============================

Структура
---------
  co2h.hhp        проект (опции компилятора, список файлов)
  co2h.hhc        оглавление (Table of Contents)
  co2h.hhk        алфавитный индекс (keyword index)
  *.html          разделы мануала
  style.css       стили

Сборка
------
1. Установить Microsoft HTML Help Workshop:
   https://learn.microsoft.com/previous-versions/windows/desktop/htmlhelp/microsoft-html-help-downloads
   (htmlhelp.exe ~3.4 MB, работает на Windows 11)

2. Запустить:

     build-chm.cmd          (или напрямую build-chm.ps1)

   Скрипт сам:
     - Создаст подпапку build/
     - Перекодирует все *.html из UTF-8 в Windows-1251
     - Заменит meta charset=UTF-8 -> charset=windows-1251
     - Скопирует .hhc/.hhk/.hhp/.css в той же кодировке
     - Запустит hhc.exe build/co2h.hhp
     - Положит co2h.chm рядом со скриптом

ВНИМАНИЕ: НЕ запускайте hhc.exe напрямую на co2h.hhp в этой папке — старый
HTML Help Workshop игнорирует <meta charset="UTF-8"> и берёт системную
кодировку (Windows-1251 на русской Windows), из-за чего кириллица
превращается в кракозябры. UTF-8 в исходниках сохраняется только для
удобства редактирования.

Просмотр без компиляции
-----------------------
Открыть index.html в браузере — все ссылки работают как обычные относительные.

Внедрение в клиент
------------------
Скопировать co2h.chm рядом с co2h_client.exe; меню Help -> Manual должно
вызывать ShellExecute("hh.exe", "co2h.chm").

Quirk hhc.exe
-------------
Microsoft hhc.exe возвращает 1 при УСПЕХЕ и 0 при ошибке. Это исторический
баг, который Microsoft никогда не исправил. build-chm.cmd обрабатывает
это правильно.

Кодировка
---------
Все .html в UTF-8 с BOM/без BOM (хватит meta charset). Если CHM-просмотрщик
покажет кракозябры на кириллице — добавить
   Language=0x419 Russian
в [OPTIONS] секции co2h.hhp (уже добавлено).
