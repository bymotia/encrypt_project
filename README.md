# Описание проекта
<h1>RSA.py</h1>
В файле RSA находится алгоритм шифрования и дешифрования
входного файла с помощью алгоритма AES и RSA.
<h2>Пример работы</h2>
Для работы с алгоритмом необходимо создать файл name.txt

Для шифрования name.txt необходимо запустить скрипт, через
python3 RSA.py ecnrypt name.txt В папке создастся два ключа: private_key.pem и public_key.pem. С ними ничего делать не надо!
Если все прошло успешно вы увидите в консоли "Encrypted"

Для дешифрования зашифрованного name.txt: python3
RSA.py decrypt name.txt. Если все прошло успешно вы увидите  в консоли "Decrypted"

<h1>interface.py</h1>

Реализован простой интерфейс формы логина - регистрации. Информация о пользователях хранится в файле users.json. Планируется защищать это файл с помощью RSA.py