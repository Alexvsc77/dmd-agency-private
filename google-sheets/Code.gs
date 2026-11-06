/** Bound to the owner's private DMD spreadsheet. No passwords or API keys. */
var DMD_API = 'https://eqhuhaolwxvtinbgubxi.supabase.co/functions/v1/dmd-api/sheets/requests';
var DMD_HEADERS = ['Дата', 'Номер заявки', 'Клиент', 'Компания', 'Контакт', 'Услуги', 'Задача', 'Бюджет', 'Получатель', 'Статус', 'Заметки'];

function onOpen() {
  SpreadsheetApp.getUi().createMenu('DMD')
    .addItem('Данные для подключения', 'showConnectionDetails')
    .addItem('Загрузить заявки сейчас', 'syncDmdRequests')
    .addSeparator()
    .addItem('Включить обновление каждую минуту', 'enableDmdSync')
    .addItem('Остановить обновление', 'disableDmdSync')
    .addToUi();
}

function showConnectionDetails() {
  var token = ScriptApp.getIdentityToken();
  if (!token) throw new Error('Разреши скрипту подтвердить твой Google-аккаунт.');
  var identity = JSON.parse(Utilities.newBlob(Utilities.base64DecodeWebSafe(token.split('.')[1])).getDataAsString());
  // These identifiers are public configuration, never the bearer token itself.
  SpreadsheetApp.getUi().alert('Подключение DMD',
    'Владелец: ' + identity.email + '\n\nDMD_GOOGLE_AUDIENCE:\n' + identity.aud +
    '\n\nDMD_GOOGLE_SUBJECT:\n' + identity.sub +
    '\n\nДобавь эти два значения в настройки Edge Function DMD в Supabase.',
    SpreadsheetApp.getUi().ButtonSet.OK);
}

function dmdSheet_() {
  // Bound-script context also works in time triggers. Limit spreadsheet access
  // to this container instead of requesting access to every owner's workbook.
  var book = SpreadsheetApp.getActiveSpreadsheet();
  if (!book) throw new Error('Сначала запусти скрипт из таблицы DMD.');
  var sheet = book.getSheetByName('Заявки');
  if (!sheet) throw new Error('Не найден лист «Заявки».');
  var actual = sheet.getRange(1, 1, 1, DMD_HEADERS.length).getDisplayValues()[0];
  if (actual.join('\t') !== DMD_HEADERS.join('\t')) {
    throw new Error('Заголовки изменены. Восстанови порядок столбцов перед загрузкой.');
  }
  return sheet;
}

function dmdFetch_(after) {
  var token = ScriptApp.getIdentityToken();
  if (!token) throw new Error('Не удалось подтвердить Google-аккаунт.');
  var response = UrlFetchApp.fetch(DMD_API + (after ? '?after=' + encodeURIComponent(after) : ''), {
    method: 'get', headers: {Authorization: 'Bearer ' + token}, muteHttpExceptions: true
  });
  var code = response.getResponseCode();
  if (code !== 200) {
    // Do not log the response, bearer token or client details.
    if (code === 503) throw new Error('Подключение не завершено или сервер временно недоступен.');
    if (code === 401 || code === 403) throw new Error('Нет доступа. Проверь аккаунт и настройки подключения DMD.');
    throw new Error('Не удалось загрузить заявки. Код ответа: ' + code);
  }
  var data = JSON.parse(response.getContentText());
  if (!Array.isArray(data.items) || data.items.length > 100 ||
      (data.next !== null && !/^DMD-[0-9a-f-]{36}$/.test(data.next))) {
    throw new Error('Сервер вернул неподдерживаемый формат заявок.');
  }
  return data;
}

function dmdText_(value) {
  var text = value == null ? '' : String(value);
  // Treat user input as text, including formulas and phone/Telegram prefixes.
  return /^[\s]*[=+\-@]/.test(text) ? "'" + text : text;
}

function dmdRow_(item) {
  if (!/^DMD-[0-9a-f-]{36}$/.test(item.id) || !Array.isArray(item.services)) {
    throw new Error('Некорректная заявка: загрузка остановлена.');
  }
  var date = new Date(item.createdAt);
  if (isNaN(date.getTime())) throw new Error('Некорректная дата заявки.');
  return [date, item.id, item.name, item.company, item.contact,
    item.services.map(function(service) { return service.title; }).join('\n'),
    item.task, item.budget, item.recipient, 'Новая', ''].map(function(value) {
      return value instanceof Date ? value : dmdText_(value);
    });
}

function syncDmdRequests() {
  var lock = LockService.getScriptLock();
  if (!lock.tryLock(1000)) return; // A previous run is still working.
  try {
    var sheet = dmdSheet_();
    var lastRow = sheet.getLastRow();
    var ids = new Set(lastRow > 1 ? sheet.getRange(2, 2, lastRow - 1, 1).getDisplayValues().map(function(row) { return row[0]; }) : []);
    var after = '';
    for (var page = 0; page < 100; page++) {
      var data = dmdFetch_(after);
      var fresh = [];
      data.items.forEach(function(item) {
        if (!ids.has(item.id)) { fresh.push(dmdRow_(item)); ids.add(item.id); }
      });
      if (fresh.length) {
        var start = sheet.getLastRow() + 1;
        var end = start + fresh.length - 1;
        if (end > sheet.getMaxRows()) sheet.insertRowsAfter(sheet.getMaxRows(), end - sheet.getMaxRows());
        var range = sheet.getRange(start, 1, fresh.length, DMD_HEADERS.length);
        range.setValues(fresh).setVerticalAlignment('top').setWrap(true);
        sheet.getRange(start, 1, fresh.length, 1).setNumberFormat('dd.MM.yyyy HH:mm');
        sheet.getRange(start, 10, fresh.length, 1).setDataValidation(
          SpreadsheetApp.newDataValidation().requireValueInList(['Новая', 'В работе', 'Завершена', 'Архив'], true).setAllowInvalid(false).build()
        );
        SpreadsheetApp.flush();
      }
      if (!data.next) {
        PropertiesService.getScriptProperties().setProperty('DMD_LAST_SYNC', new Date().toISOString());
        return;
      }
      if (data.next <= after) throw new Error('Страница не изменилась: загрузка остановлена.');
      after = data.next;
    }
    throw new Error('Достигнут предел 10 000 заявок за загрузку. Требуется расширить способ синхронизации.');
  } finally { lock.releaseLock(); }
}

function enableDmdSync() {
  var book = SpreadsheetApp.getActiveSpreadsheet();
  book.setSpreadsheetTimeZone('Europe/Moscow');
  // First verify the connection. Keep any existing trigger when verification fails.
  syncDmdRequests();
  disableDmdSync();
  ScriptApp.newTrigger('syncDmdRequests').timeBased().everyMinutes(1).create();
  book.toast('Обновление включено. Новые заявки появятся автоматически.', 'DMD');
}

function disableDmdSync() {
  ScriptApp.getProjectTriggers().forEach(function(trigger) {
    if (trigger.getHandlerFunction() === 'syncDmdRequests') ScriptApp.deleteTrigger(trigger);
  });
}
