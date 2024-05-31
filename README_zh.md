[繁體中文] | [English](README.md)
# YaraForge
YaraForge 是一個 IDA Pro 的插件,用於從二進制文件生成 Yara 規則。它利用 CAPA 分析的結果,自動生成對應的 Yara 規則,幫助安全研究人員和逆向工程師快速識別和檢測惡意軟件。
## 功能特點

* 自動從 CAPA 分析結果中提取關鍵信息,生成 Yara 規則
* 支持導出 CAPA 分析結果的詳細信息,包括匹配的規則、地址等
* 可以將生成的 Yara 規則和相關信息保存到本地文件中
* 提供友好的用戶界面,方便用戶操作和配置
* 內置詳細的日誌記錄功能,便於問題排查和調試

## 安裝方法

1. 使用 pip 安裝 YaraForge:
```shell
pip install yaraforge
```
2. 將 `yaraforge/plugin`資料夾內的`yaraforge.py` 檔案複製到 IDA Pro 的 `plugins` 目錄中。
3. 啟動 IDA Pro,YaraForge 插件會自動加載。

## 使用方法

1. 在 IDA Pro 中打開目標二進制文件。
2. 運行 CAPA 分析,確保生成了分析結果。
3. 使用 Ctrl+Y 快捷鍵或在 IDA Pro 的菜單欄中選擇 "Edit" -> "Plugins" -> "YaraForge" 來啟動插件。
4. 插件會自動從 CAPA 分析結果中提取信息,生成對應的 Yara 規則。
5. 生成的 Yara 規則和相關信息默認保存在 `%APPDATA%\Hex-Rays\IDA Pro\plugins\yaraforge\` 資料夾中。
6. 如果需要導出分析結果到桌面,可以在插件界面中選擇 "Dump Caches on desktop" 選項。

## 注意事項

* YaraForge 插件依賴於 CAPA 進行分析,安裝插件時會自動下載和安裝 CAPA,無需用戶手動安裝。
* 插件生成的 Yara 規則僅供參考,可能需要根據實際情況進行調整和優化。
* 插件的部分功能依賴於 IDA Pro 的 API,不同版本的 IDA Pro 可能存在兼容性問題,如遇到問題,請參考插件的錯誤日誌和相關文檔，或回報給我。

## 作者

* Zhao Xinn (zhaoxinzhang0429@gmail.com)
* Tsai YA-HSUAN (aooood456@gmail.com)
* Ting0525 (zg45154551@gmail.com)

## 特別感謝
我們誠摯感謝 [DuckLL](https://github.com/DuckLL)，他對於指導我們投入了大量的關注與耐心。 他的重大貢獻和創新想法對本專案的發展方向有著顯著的影響。

## 版本要求

* Python: >=3.8, <3.12
* CAPA: 7.0.1
* IDA Pro: >=7.0
* Windows 7/8/10/11

## 許可證
* YaraForge 插件遵循 MIT 許可證,詳情請參閱 [LICENSE](LICENSE) 文件。
## 致謝
YaraForge 插件的開發得到了眾多開源項目和社區的幫助和啟發,在此表示感謝!

* CAPA: https://github.com/fireeye/capa
* Capstone: https://github.com/aquynh/capstone
* mkYARA: https://github.com/fox-it/mkYARA
* IDA Pro: 著名的商業反編譯和調試軟件

## 聯繫方式
如果您在使用 YaraForge 插件的過程中遇到任何問題,或者有任何建議和反饋,歡迎通過以下方式聯繫我們:

* GitHub Issues: https://github.com/zhaoxinnZ/YaraForge/issues
* 信箱: zhaoxinzhang0429@gmail.com

感謝您的支持和關注!希望 YaraForge 能夠成為您二進制分析和 Yara 規則生成的得力助手。