; ===========================================================================
; A-62 selftest: per-user инсталлятор БЕЗ elevation, который прогоняет
; [Code]-логику прод-инсталлятора (генерация bootstrap-админа, merge
; config.env, admin-credentials.txt при silent-установке) живьём на реальном
; Windows + Inno Setup. Инклюдит РОВНО тот же installer-admin.iss, что и
; installer.iss — дублирования логики нет; единственное отличие —
; #define AdminDataDir на scratch-каталог ({localappdata}\Hranix-A62-Selftest),
; чтобы реальные данные пользователя (%LOCALAPPDATA%\Hranix\Hranix Shield) не
; затрагивались в принципе.
;
; Смысл: полноценная прод-установка требует elevation (PrivilegesRequired=admin
; в installer.iss) и живого UAC-подтверждения, которого автоматизированная
; сессия дать не может. Этот скрипт ставится в {localappdata}\Programs без
; прав администратора и проверяет всю ту же логику; сценарии прогонов —
; в test/run-a62-selftest.sh. Сборка:
;   "<ISCC.exe>" test\a62-admin-selftest.iss   (из packaging/windows)
; Прогон:
;   test\dist\a62-selftest\hranix-a62-admin-selftest.exe /VERYSILENT /SUPPRESSMSGBOXES
; Снос после прогонов: unins000.exe из каталога установки (+ run-a62-selftest.sh
; делает это сам).
; ===========================================================================

#define MyAppName "Hranix A62 Admin Selftest"
#define AdminDataDir "{localappdata}\Hranix-A62-Selftest"

; [Languages] обязателен: [CustomMessages] инклюда объявляет ключи с префиксами
; english./russian., и без объявленных языков парсер падает с
; «Unknown language name».
[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[Setup]
; Отдельный одноразовый GUID, сгенерирован для этого selftest (uuid4),
; прод-AppId installer.iss не пересекается.
AppId={{5DC3C1B3-5E31-4379-B0CD-78A2DFE411A1}
AppName={#MyAppName}
AppVersion=0.1.0
AppPublisher=Hranix
; Ставится в профиль текущего пользователя — UAC/elevation не запрашивается
; вообще (PrivilegesRequired=lowest), поэтому selftest можно запускать
; автоматически из скрипта.
PrivilegesRequired=lowest
DefaultDirName={localappdata}\Programs\HranixA62Selftest
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
DisableDirPage=yes
DisableReadyPage=yes
OutputDir=dist\a62-selftest
OutputBaseFilename=hranix-a62-admin-selftest
Compression=none
SolidCompression=no
WizardStyle=modern
; Деинсталлятор нужен (run-a62-selftest.sh сносит им установку и записи
; реестра), никаких [Files]/[Tasks]/[Run]/[Icons] сам не требует: важно
; только CurStepChanged-поведение installer-admin.iss.
;
; #include — ПОСЛЕДНЕЙ строкой файла: парсер Inno после включённого файла не
; распознаёт новые секционные заголовки (проверено компиляцией 2026-09-21:
; «BEGIN expected» на следующей за include секции), а внутри include как раз
; [CustomMessages] + [Code].
#include "..\installer-admin.iss"
