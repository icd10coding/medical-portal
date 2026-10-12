# 學生練習區・Coding Clinic 題庫（student/cc/）

網址：https://icd10coding.github.io/medical-portal/student/cc/

## 保護方式

- 公開頁 `student/index.html` 只含歷屆考題與 2027 年版指引題，**不含** Coding Clinic 題目。
- Coding Clinic 題庫放在完整練習頁 `student/cc/app.bin`，以隨機內容金鑰（AES-256-GCM）加密後才放進這個公開 repo。沒有帳號密碼無法解開。
- 每個帳號以自己的密碼（PBKDF2-SHA256，600,000 次）包裝同一把內容金鑰，存在 `student/cc/users.json`；帳號名稱只存雜湊值。
- 登入與解密都在使用者的瀏覽器內進行。這套帳號與「病歷編碼工作台（coder/）」各自獨立。

## 帳號管理

到 `student/cc/admin.html` 以管理員登入，可新增帳號、重設密碼、刪除帳號、變更自己的密碼。
完成後下載新的 `users.json`，上傳到 repo 的 `student/cc/` 資料夾覆蓋原檔即生效。

## 更新題庫

未加密的完整練習頁（含題庫）不放在這個 repo。取得新的完整練習頁後，以管理員帳號執行（Node 18 以上）：

```
CODER_USER=admin CODER_PASS='管理員密碼' node tools/student/build.mjs build --src <完整練習頁.html>
```

其他指令：`list`、`adduser <帳號> [--role admin|user]`（需 `NEW_PASS`），說明見 `build.mjs` 開頭。
