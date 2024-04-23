功能:搜尋客戶端C/C++ SOURCE CODE中使用到的第三方LIB。

10行:C/C++標準LIB。
12行:將資料輸入到sample.sbom.json的檔案格式中。
14-15行:現在時間。
20-33行:搜尋#include及-l的字串。
34-42行:排出標準LIB和重複的LIB。


輸出格式:
{
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "version": 1,
    "metadata": {
        "timestamp": "2023-12-19T03:40:10",
        "tools": [
            {
                "vendor": "III CSTI",
                "name": "UFO",
                "version": "0.0.0.0"
            }
        ]
    },
    "components": [
        {
            "type": "file",
            "name": "openssl/md5.h"
        },
        {
            "type": "library",
            "name": "ssl"
        },]
