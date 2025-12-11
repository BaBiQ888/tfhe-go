## tfhe-go 后端服务

一套使用 Go 对接 `tfhe-c` C API 的示例后端，提供布尔同态加解密与运算接口。

### 项目结构
- `cmd/server/`：服务入口。
- `internal/tfhe/`：cgo 绑定与高阶封装（密钥管理、序列化）。
- `internal/httpapi/`：HTTP 路由与请求处理。
- `tfhe-c/release/`：C 头文件与编译好的 `libtfhe`。
 
### 运行

### 运行
1. 确认本地已编译好 `tfhe-c/release/libtfhe.dylib` 且与 `tfhe.h` 同目录。
2. Go 版本 1.22+。在项目根目录执行：
   ```bash
   go run ./cmd/server
   ```
3. 服务默认监听 `:8080`。

### HTTP API（JSON）
- `GET /health` → `{ "status": "ok" }`
- `POST /boolean/encrypt` body: `{ "value": true }` → `{ "ciphertext": "<b64>" }`
- `POST /boolean/decrypt` body: `{ "ciphertext": "<b64>" }` → `{ "value": true }`
- `POST /boolean/and|or|xor` body: `{ "left": "<b64>", "right": "<b64>" }` → `{ "ciphertext": "<b64>" }`
- `POST /boolean/not` body: `{ "ciphertext": "<b64>" }` → `{ "ciphertext": "<b64>" }`
- `POST /uint8/encrypt` body: `{ "value": 7 }` → `{ "ciphertext": "<b64>" }`
- `POST /uint8/encrypt/public` body: `{ "value": 7 }` → `{ "ciphertext": "<b64>" }`
- `POST /uint8/decrypt` body: `{ "ciphertext": "<b64>" }` → `{ "value": 7 }`
- `POST /uint8/add|bitand|bitxor` body: `{ "left": "<b64>", "right": "<b64>" }` → `{ "ciphertext": "<b64>" }`

### 说明
- 服务启动时自动使用默认参数生成布尔 Client/Server Key。
- 整数（uint8）服务使用默认 ConfigBuilder 生成 Client/Server/Public Key，并自动 set_server_key。
- 所有密文以 base64 传输；内部使用 `tfhe-c` 序列化/反序列化。
- 目前示例覆盖布尔与 uint8，可按相同模式扩展其他整数类型运算。

