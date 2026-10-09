# 病歷編碼工作台（coder/）

網址：https://icd10coding.github.io/medical-portal/coder/

## 保護方式

- 工作台網頁（`coder/app.bin`）與資料檔（`coder/data/*.bin`）都以一把隨機內容金鑰（AES-256-GCM）加密後才放進這個公開 repo。沒有帳號密碼就無法解開。
- 每個帳號以自己的密碼（PBKDF2-SHA256，600,000 次）包裝同一把內容金鑰，存在 `coder/users.json`。帳號名稱只存雜湊值，檔案內看不到誰有帳號。
- 登入、解密、編碼、分組全部在使用者的瀏覽器內進行，病歷內容不會送到任何伺服器。
- 公開的檔案只有登入頁 `coder/index.html`、帳號管理頁 `coder/admin.html`、`coder/crypto.js` 與這個工具。

## 帳號管理

到 `coder/admin.html` 以管理員登入，可新增帳號、重設密碼、刪除帳號、變更自己的密碼。
完成後下載新的 `users.json`，上傳到 repo 的 `coder/` 資料夾覆蓋原檔即生效。

刪除帳號後對方下次開啟就無法登入。若要確保對方無法再使用先前已下載的資料，需重建內容金鑰（`init`）並請所有人重設密碼。

## 更新內容（例如健保署分類表、工具書、索引改版）

來源檔（未加密）不放在這個 repo。準備好來源資料夾：

```
<來源資料夾>/app.html
<來源資料夾>/data/twdrg.json.gz
<來源資料夾>/data/icdref.json.gz
<來源資料夾>/data/refs.json.gz
```

然後以管理員帳號執行（Node 18 以上）：

```
CODER_USER=admin CODER_PASS='管理員密碼' node tools/coder/build.mjs build --src <來源資料夾>
```

其他指令：`list`（列出帳號）、`adduser <帳號> [--role admin|user]`（需 `NEW_PASS`），說明見 `build.mjs` 開頭。
