; ===========================================================================
; A-62: bootstrap-администратор панели, создаваемый инсталлятором
; автоматически. Вся [Code]-логика вынесена в этот include-файл, чтобы она
; существовала в РОВНО одном экземпляре: его инклюдит прод-installer.iss и
; packaging/windows/test/a62-admin-selftest.iss — per-user инсталлятор БЕЗ
; elevation, который прогоняет те же самые функции живьём на реальном
; Windows + Inno Setup (см. test/run-a62-selftest.sh; единственное отличие —
; #define AdminDataDir на scratch-каталог, чтобы реальные данные
; пользователя не затрагивались в принципе).
;
; Что происходит на CurStepChanged(ssPostInstall):
;   - если <data>\config.env уже содержит непустой BOOTSTRAP_ADMIN_USERNAME —
;     ничего не делаем: апгрейд поверх рабочей установки и CI-сценарий
;     (windows-build.yml пишет config.env отдельным шагом ДО установки)
;     не затрагиваются;
;   - иначе генерируем логин admin + криптостойкий пароль (20 символов,
;     [A-Za-z0-9], BCryptGenRandom) и домерживаем ключи в config.env по тому
;     же принципу, что _merge_env_file в services/stack/bootstrap.py (A-60):
;     существующие непустые значения не затираются, пустые заполняются,
;     отсутствующие дописываются, чужие ключи/комментарии сохраняются
;     байт-в-байт;
;   - интерактивная установка: креденшелы показываются на финальной странице
;     мастера (готовый к копированию блок + предупреждение «сохраните»);
;   - silent-установка (/SILENT и /VERYSILENT): финальная страница не
;     показывается ВООБЩЕ, поэтому креденшелы дополнительно пишутся в
;     <data>\admin-credentials.txt (файл наследует ACL профиля пользователя —
;     отдельная настройка ACL не нужна); без этого сгенерированный при
;     silent-установке пароль не попал бы ни на экран, ни на диск.
; ===========================================================================

#ifndef AdminDataDir
#define AdminDataDir "{localappdata}\Hranix\Hranix Shield"
#endif

[CustomMessages]
english.AdminCredentialsTitle=Your Hranix Shield admin account
english.AdminCredentialsWarning=Save this password now - it will not be shown again. Change it after your first sign-in.
english.AdminCredentialsUsername=Username:
english.AdminCredentialsPassword=Password:
english.AdminSetupFailed=The installer could not create the panel admin account (%1). Setup will continue - the account can be created manually later, see the "Create your admin account" section of the README.
russian.AdminCredentialsTitle=Ваша учётная запись администратора Hranix Shield
russian.AdminCredentialsWarning=Сохраните пароль прямо сейчас - он больше не будет показан. Смените его после первого входа в панель.
russian.AdminCredentialsUsername=Логин:
russian.AdminCredentialsPassword=Пароль:
russian.AdminSetupFailed=Инсталлятор не смог создать учётную запись администратора панели (%1). Установка продолжится - аккаунт можно создать вручную позже, см. раздел «Создайте аккаунт администратора» в README.

[Code]

const
  // Логин фиксирован план-спецификацией A-62: панель однопользовательская
  // (single-tenant), других учётных записей инсталлятор не создаёт.
  AdminBootstrapUsername = 'admin';
  AdminPasswordLength = 20;
  AdminPasswordAlphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  // 256 mod 62 = 8: байты >= 248 отбрасываются (rejection sampling), иначе
  // остаток от деления давал бы первым восьми символам алфавита ~3%-й сдвиг
  // вероятности относительно остальных.
  AdminPasswordUnbiasedMax = 248;
  BCRYPT_USE_SYSTEM_PREFERRED_RNG = $2;

var
  // '' = генерации не было (апгрейд поверх настроенного config.env или
  // ошибка): финальная страница ничего не показывает, файл креденшелов
  // не пишется.
  GeneratedAdminPassword: string;
  CredentialsTitle: TNewStaticText;
  CredentialsWarningLabel: TNewStaticText;
  CredentialsMemo: TNewMemo;

// Документированный CSPRNG Windows (bcrypt.dll, Vista+). Флаг
// BCRYPT_USE_SYSTEM_PREFERRED_RNG означает «возьми системный
// предпочтительный алгоритм сам» — hAlgorithm при этом не открывается.
// Возврат — NTSTATUS: 0 = успех.
function BCryptGenRandom(hAlgorithm: THandle; pbBuffer: PAnsiChar;
  cbBuffer: Cardinal; dwFlags: Cardinal): Longint;
  external 'BCryptGenRandom@bcrypt.dll stdcall';

// Крипостойкий пароль длины AdminPasswordLength из AdminPasswordAlphabet.
// Ошибка CSPRNG (на практике не встречается) даёт '' — вызывающий код честно
// сообщает о неудаче, а не подставляет слабую fallback-замену.
function GenerateAdminPassword: string;
var
  Buffer: AnsiString;
  ByteIndex: Integer;
  ByteValue: Integer;
  Password: string;
begin
  Result := '';
  Password := '';
  while Length(Password) < AdminPasswordLength do
  begin
    SetLength(Buffer, AdminPasswordLength * 2);
    if BCryptGenRandom(0, PAnsiChar(Buffer), Length(Buffer),
       BCRYPT_USE_SYSTEM_PREFERRED_RNG) <> 0 then
      Exit;
    for ByteIndex := 1 to Length(Buffer) do
    begin
      ByteValue := Ord(Buffer[ByteIndex]);
      if ByteValue < AdminPasswordUnbiasedMax then
        Password := Password +
          AdminPasswordAlphabet[(ByteValue mod Length(AdminPasswordAlphabet)) + 1];
      if Length(Password) >= AdminPasswordLength then
        Break;
    end;
  end;
  Result := Password;
end;

// Читает config.env как БАЙТЫ (AnsiString). Отсутствующий файл — нормальный
// путь «создать с нуля» (True, пустой Content); нечитаемый существующий
// файл (ACL/диск) — False, наверх честной ошибки, не молчаливой подмены.
function LoadEnvFile(const EnvPath: string; var Content: AnsiString): Boolean;
begin
  Content := '';
  if not FileExists(EnvPath) then
  begin
    Result := True;
    Exit;
  end;
  Result := LoadStringFromFile(EnvPath, Content);
end;

function SaveEnvFile(const EnvPath: string; const Content: AnsiString): Boolean;
begin
  Result := ForceDirectories(ExtractFileDir(EnvPath));
  if Result then
    Result := SaveStringToFile(EnvPath, Content, False);
end;

// Сканирует содержимое KEY=VALUE-файла на вхождения строки `Key=`. Семантика
// совпадает с parse_env_file в services/stack/bootstrap.py (A-60): пробелы
// вокруг ключа и значения не значимы, `#`-комментарии и пустые строки
// пропускаются, «настроено» = есть вхождение с непустым значением. Позиции
// — байтовые (1-based, включительно): пользовательские значения не обязаны
// быть ASCII, а конверсия кодировок могла бы тихо испортить их при обратной
// записи. FirstFrom = 0 — вхождений нет; FirstFrom > FirstTo — вхождение с
// пустым значением (чистая вставка); иначе FirstFrom..FirstTo — заменяемый
// диапазон значения.
procedure ScanEnvContent(const Content: AnsiString; const Key: string;
  var HasNonEmpty: Boolean; var FirstFrom, FirstTo: Integer);
var
  KeyEquals: AnsiString;
  KeyEqualsLength: Integer;
  Position, LineEnd, KeyStart, ValueStart, ValueEnd: Integer;
  ContentLength: Integer;
begin
  HasNonEmpty := False;
  FirstFrom := 0;
  FirstTo := 0;
  KeyEquals := AnsiString(Key + '=');
  KeyEqualsLength := Length(KeyEquals);
  ContentLength := Length(Content);
  Position := 1;
  while Position <= ContentLength do
  begin
    LineEnd := Position;
    while (LineEnd <= ContentLength) and (Content[LineEnd] <> #10) do
      LineEnd := LineEnd + 1;
    KeyStart := Position;
    while (KeyStart < LineEnd) and
          ((Content[KeyStart] = ' ') or (Content[KeyStart] = #9)) do
      KeyStart := KeyStart + 1;
    if KeyStart + KeyEqualsLength - 1 <= LineEnd then
    begin
      if Copy(Content, KeyStart, KeyEqualsLength) = KeyEquals then
      begin
        ValueStart := KeyStart + KeyEqualsLength;
        ValueEnd := LineEnd - 1;
        while (ValueEnd >= ValueStart) and
              ((Content[ValueEnd] = ' ') or (Content[ValueEnd] = #9) or
               (Content[ValueEnd] = #13)) do
          ValueEnd := ValueEnd - 1;
        if FirstFrom = 0 then
        begin
          FirstFrom := ValueStart;
          FirstTo := ValueEnd;
        end;
        if ValueEnd >= ValueStart then
          HasNonEmpty := True;
      end;
    end;
    Position := LineEnd + 1;
  end;
end;

// Точечная вставка/замена значения. Пустой диапазон (FirstTo < FirstFrom)
// означает вставку без удаления — так сохраняются конечный CR и хвостовые
// пробелы исходной строки.
function ReplaceValueInContent(const Content: AnsiString; FromPos, ToPos: Integer;
  const Value: string): AnsiString;
begin
  if ToPos < FromPos then
    Result := Copy(Content, 1, FromPos - 1) + AnsiString(Value) +
      Copy(Content, FromPos, MaxInt)
  else
    Result := Copy(Content, 1, FromPos - 1) + AnsiString(Value) +
      Copy(Content, ToPos + 1, MaxInt);
end;

function ExistingAdminConfigured(const EnvPath: string): Boolean;
var
  Content: AnsiString;
  HasNonEmpty: Boolean;
  FirstFrom, FirstTo: Integer;
begin
  Result := False;
  if LoadEnvFile(EnvPath, Content) then
  begin
    ScanEnvContent(Content, 'BOOTSTRAP_ADMIN_USERNAME', HasNonEmpty,
      FirstFrom, FirstTo);
    Result := HasNonEmpty;
  end;
end;

// Домерживает BOOTSTRAP_ADMIN_USERNAME/PASSWORD в config.env (принцип
// _merge_env_file, A-60): непустые существующие значения не затираются,
// пустые заполняются, отсутствующие дописываются в конец. Контракт: вызывается
// только когда username ещё не настроен. Непустой пароль при пустом username —
// битая конфигурация (ensure_bootstrap_admin требует оба), заменяется свежим,
// чтобы показанная пара была рабочей; «чужие» ключи и комментарии это не
// затрагивает.
function MergeAdminCredentials(const EnvPath, Username, Password: string): Boolean;
var
  Content: AnsiString;
  HasNonEmpty: Boolean;
  FirstFrom, FirstTo: Integer;
  AppendText: string;
  Changed: Boolean;
begin
  if not LoadEnvFile(EnvPath, Content) then
  begin
    Result := False;
    Exit;
  end;
  Changed := False;

  ScanEnvContent(Content, 'BOOTSTRAP_ADMIN_USERNAME', HasNonEmpty,
    FirstFrom, FirstTo);
  if HasNonEmpty then
  begin
    // уже настроен — не трогаем (защита от прямого вызова)
    Result := True;
    Exit;
  end;
  if FirstFrom > 0 then
  begin
    Content := ReplaceValueInContent(Content, FirstFrom, FirstTo, Username);
    Changed := True;
  end;

  ScanEnvContent(Content, 'BOOTSTRAP_ADMIN_PASSWORD', HasNonEmpty,
    FirstFrom, FirstTo);
  if FirstFrom > 0 then
  begin
    Content := ReplaceValueInContent(Content, FirstFrom, FirstTo, Password);
    Changed := True;
  end;

  AppendText := '';
  ScanEnvContent(Content, 'BOOTSTRAP_ADMIN_USERNAME', HasNonEmpty,
    FirstFrom, FirstTo);
  if FirstFrom = 0 then
    AppendText := AppendText + 'BOOTSTRAP_ADMIN_USERNAME=' + Username + #13#10;
  ScanEnvContent(Content, 'BOOTSTRAP_ADMIN_PASSWORD', HasNonEmpty,
    FirstFrom, FirstTo);
  if FirstFrom = 0 then
    AppendText := AppendText + 'BOOTSTRAP_ADMIN_PASSWORD=' + Password + #13#10;
  if AppendText <> '' then
  begin
    if (Length(Content) > 0) and (Content[Length(Content)] <> #10) then
      AppendText := #13#10 + AppendText;
    Content := Content + AnsiString(AppendText);
    Changed := True;
  end;

  if not Changed then
  begin
    Result := True;
    Exit;
  end;
  Result := SaveEnvFile(EnvPath, Content);
end;

// admin-credentials.txt строго ASCII: файл для CI/enterprise-автоматизации,
// где лишние кодировки ломают парсеры.
function BuildCredentialsFileText(const Username, Password: string): AnsiString;
begin
  Result := AnsiString(
    '# Hranix Shield panel admin account, auto-generated by the installer' + #13#10 +
    '# (silent setup: the wizard page that shows the password is not shown).' + #13#10 +
    '# Sign in at http://127.0.0.1:<SERVER_PORT from config.env, default 8080>' + #13#10 +
    '# and change this password.' + #13#10 +
    'BOOTSTRAP_ADMIN_USERNAME=' + Username + #13#10 +
    'BOOTSTRAP_ADMIN_PASSWORD=' + Password + #13#10);
end;

procedure CreateCredentialsControls;
var
  Left: Integer;
begin
  Left := WizardForm.RunList.Left;

  CredentialsTitle := TNewStaticText.Create(WizardForm);
  CredentialsTitle.Parent := WizardForm;
  CredentialsTitle.Left := Left;
  CredentialsTitle.Top := 0;
  CredentialsTitle.Font.Style := [fsBold];
  CredentialsTitle.Visible := False;

  CredentialsWarningLabel := TNewStaticText.Create(WizardForm);
  CredentialsWarningLabel.Parent := WizardForm;
  CredentialsWarningLabel.Left := Left;
  CredentialsWarningLabel.Top := 0;
  CredentialsWarningLabel.WordWrap := True;
  CredentialsWarningLabel.Font.Color := clRed;
  CredentialsWarningLabel.Visible := False;

  CredentialsMemo := TNewMemo.Create(WizardForm);
  CredentialsMemo.Parent := WizardForm;
  CredentialsMemo.Left := Left;
  CredentialsMemo.Top := 0;
  CredentialsMemo.ReadOnly := True;
  CredentialsMemo.ScrollBars := ssVertical;
  CredentialsMemo.WordWrap := False;
  CredentialsMemo.Font.Name := 'Consolas';
  CredentialsMemo.Anchors := [akLeft, akRight, akTop];
  CredentialsMemo.Visible := False;
end;

function MaxOf(const A, B: Integer): Integer;
begin
  if A > B then
    Result := A
  else
    Result := B;
end;

function MinOf(const A, B: Integer): Integer;
begin
  if A < B then
    Result := A
  else
    Result := B;
end;

procedure ShowCredentialsBlock;
var
  BaseY, AvailableBottom, BlockWidth: Integer;
begin
  CredentialsTitle.Caption := CustomMessage('AdminCredentialsTitle');
  CredentialsWarningLabel.Caption := CustomMessage('AdminCredentialsWarning');
  CredentialsMemo.Text :=
    CustomMessage('AdminCredentialsUsername') + ' ' + AdminBootstrapUsername + #13#10 +
    CustomMessage('AdminCredentialsPassword') + ' ' + GeneratedAdminPassword;

  BlockWidth := WizardForm.ClientWidth - 2 * CredentialsMemo.Left;
  CredentialsWarningLabel.Width := BlockWidth;
  CredentialsMemo.Width := BlockWidth;

  BaseY := WizardForm.FinishedLabel.Top + WizardForm.FinishedLabel.Height;
  if WizardForm.RunList.Visible then
    BaseY := MaxOf(BaseY, WizardForm.RunList.Top + WizardForm.RunList.Height);

  CredentialsTitle.Top := BaseY + ScaleY(12);
  CredentialsWarningLabel.Top := CredentialsTitle.Top + CredentialsTitle.Height + ScaleY(4);
  CredentialsMemo.Top :=
    CredentialsWarningLabel.Top + CredentialsWarningLabel.Height + ScaleY(6);

  AvailableBottom := WizardForm.ClientHeight - ScaleY(16);
  CredentialsMemo.Height :=
    MinOf(ScaleY(56), MaxOf(ScaleY(28), AvailableBottom - CredentialsMemo.Top));

  CredentialsTitle.Visible := True;
  CredentialsWarningLabel.Visible := True;
  CredentialsMemo.Visible := True;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  DataDir, EnvPath, CredentialsPath, Password: string;
begin
  if CurStep <> ssPostInstall then
    Exit;
  DataDir := ExpandConstant('{#AdminDataDir}');
  EnvPath := AddBackslash(DataDir) + 'config.env';
  if ExistingAdminConfigured(EnvPath) then
    Exit;
  Password := GenerateAdminPassword;
  if Password = '' then
  begin
    if not WizardSilent() then
      MsgBox(
        Format(CustomMessage('AdminSetupFailed'), ['random password generation failed']),
        mbError, MB_OK);
    Exit;
  end;
  if not MergeAdminCredentials(EnvPath, AdminBootstrapUsername, Password) then
  begin
    if not WizardSilent() then
      MsgBox(
        Format(CustomMessage('AdminSetupFailed'), ['could not update ' + EnvPath]),
        mbError, MB_OK);
    Exit;
  end;
  GeneratedAdminPassword := Password;
  if WizardSilent() then
  begin
    // /SILENT и /VERYSILENT оба не показывают финальную страницу — без файла
    // сгенерированный пароль не увидеть нигде.
    CredentialsPath := AddBackslash(DataDir) + 'admin-credentials.txt';
    SaveStringToFile(CredentialsPath,
      BuildCredentialsFileText(AdminBootstrapUsername, Password), False);
  end;
end;

procedure InitializeWizard;
begin
  CreateCredentialsControls;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if CurPageID = wpFinished then
  begin
    if GeneratedAdminPassword <> '' then
      ShowCredentialsBlock;
  end
  else
  begin
    if CredentialsTitle <> nil then
      CredentialsTitle.Visible := False;
    if CredentialsWarningLabel <> nil then
      CredentialsWarningLabel.Visible := False;
    if CredentialsMemo <> nil then
      CredentialsMemo.Visible := False;
  end;
end;
